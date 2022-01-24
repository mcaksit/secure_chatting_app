from abc import abstractmethod
from random import randint, seed
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random
import math
import time
import random
# import sympy
import warnings
import sys
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import re
import json
from base64 import b64encode

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

data = ["0\n"] * 18

try:
    with open('client_info.txt', 'r') as file:
        data = file.readlines()
except:
    data[0] = "00000\n"
    data[1] = "35651698880052121804585259127534554484441448228508139122581799467091687874239\n"
    data[2] = "496284\n"
    data[3] = "414175\n"
    data[4] = "109713584734299482578504860572597562168957409548972646669134073184529407086806\n"
    data[5] = "85040781858568445399879179922879835942032506645887434621361669108644661638219\n"
    data[6] = "46354559534391251764410704735456214670494836161052287022185178295305851364841\n"
    data[7] = "73947339966248560923888334669533474159421374825181141806049754594437808838256\n"
    data[8] = "96664679490819739841131421806458690459450258812110637405274410293157097686077\n"
    data[9] = "34517748805177427607379391743247211650169741833985330308633060943827225164795\n"
    data[10] = "23321602045516064852119907004451406442333048607123200577704569092175772276527\n"
    data[11] = "110645034498631311138077187312223214575438151650863558250949832549085704791431\n"
    data[12] = "11685636074747614800037263916210003031777894446891019973957605530438719385017\n"
    data[13] = "2564368159424152020965769270916318908058317349658833940214690235545248086559\n"
    data[14] = "89339811726384727136749261445914205670990113583644894189349991811759886628393\n"
    data[15] = "19489193086507177055422617218200071982051228352676497021309541490884285328385\n"
    data[16] = "105630090613882340577407392578366520791269664081855422853677772570186276987348\n"
    data[17] = "10\n"
    
stuID = int(data[0])
IK_Pri = int(data[1])
IK_Pub = IK_Pri * P
auth_code = int(data[2])
rcode = int(data[3])
SPK_Pri = int(data[4])
SPK_Pub = SPK_Pri * P
server_pub_x = int(data[5])
server_pub_y = int(data[6])
server_pub = Point(server_pub_x, server_pub_y, E)
OTKs_Pri = []
for i in range(7,17):
    OTKs_Pri.append(int(data[i]))
OTKs_last_id = int(data[17])

def WriteToFile(line_no, val):
    global data
    data[line_no] = str(val) + '\n'
    
    with open('client_info.txt', 'w') as file:
        file.writelines(data)

# Client Basics ------------------------------------------------------------------------------------------

#server's Identitiy public key
API_URL = 'server_URL'

IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, E)

#Send Public Identitiy Key Coordinates and corresponding signature
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

#Send the verification code
def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

#Send SPK Coordinates and corresponding signature
def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

#Send OTK Coordinates and corresponding hmac
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
#Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

#get your messages. server will send 1 message from your inbox 
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA":idA, "IDB":idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json = mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json = OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']      
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)	
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']	

# 2.4 ------------------------------------------------------------------------------------------------------

def keyGen():
    global n, P
    pri = randint(1,n-2)
    pub = pri * P
    return pri, pub

def sigGen(m, pri):
    global n, P
    k = Random.new().read(int(math.log(n,2)))
    k = int.from_bytes(k, byteorder='big') % n
    R = k * P
    r = R.x % n
    r_bytes = r.to_bytes(length = (r.bit_length()+7) // 8 , byteorder = 'big')
    if type(m) != bytes:
        m_bytes = m.to_bytes(length = (m.bit_length()+7) // 8 , byteorder = 'big')
    else:
        m_bytes = m
    hash_value = SHA3_256.new(r_bytes + m_bytes)
    h = int.from_bytes(hash_value.digest() , 'big') % n
    s = (k - pri * h) % n

    return h, s

def sigVer(h, s, pub, m):
    global n, P
    V = s * P + h * pub
    v = V.x % n
    v_bytes = v.to_bytes(length = (v.bit_length()+7) // 8 , byteorder = 'big')
    if type(m) != bytes:
        m_bytes = m.to_bytes(length = (m.bit_length()+7) // 8 , byteorder = 'big')
    else:
        m_bytes = m
    hash_value_prime = SHA3_256.new(v_bytes + m_bytes)
    h_prime = int.from_bytes(hash_value_prime.digest() , 'big') % n

    if h == h_prime:
        print("Signiture is verified!")
        # return True
    else:
        print("Signiture can't be verified!")
        # return False

# 2.1 ------------------------------------------------------------------------------------------------------

def Register_IK():
    global IK_Pri, IK_Pub, stuID
    IK_Pri, IK_Pub = keyGen()
    WriteToFile(1, IK_Pri)
    print("IK Private: ",IK_Pri)

    h, s = sigGen(stuID, IK_Pri)

    sigVer(h, s, IK_Pub, stuID)

    IKRegReq(h, s, IK_Pub.x, IK_Pub.y)

def Authenticate_IK(auth_code):
    IKRegVerify(auth_code)
 
def Reset_IK(rcode):
    ResetIK(rcode)

# 2.2 ------------------------------------------------------------------------------------------------------

def Register_Validate_SPK():
    global SPK_Pri, SPK_Pub, server_pub, IK_Pri
    SPK_Pri, SPK_Pub = keyGen()
    WriteToFile(4, SPK_Pri)
    print("SPK Private: ",SPK_Pri)

    SPK_Pub_x_bytes = SPK_Pub.x.to_bytes(length = (SPK_Pub.x.bit_length()+7) // 8 , byteorder = 'big')
    SPK_Pub_y_bytes = SPK_Pub.y.to_bytes(length = (SPK_Pub.y.bit_length()+7) // 8 , byteorder = 'big')
    m_SPK = SPK_Pub_x_bytes + SPK_Pub_y_bytes

    h_spk, s_spk = sigGen(m_SPK, IK_Pri)

    server_res = SPKReg(h_spk,s_spk,SPK_Pub.x,SPK_Pub.y)
    server_x, server_y, server_h, server_s = server_res
    WriteToFile(5, server_x)
    WriteToFile(6, server_y)
    server_pub = Point(server_x, server_y, E)

    server_x_bytes = server_x.to_bytes(length = (server_x.bit_length()+7) // 8 , byteorder = 'big')
    server_y_bytes = server_y.to_bytes(length = (server_y.bit_length()+7) // 8 , byteorder = 'big')
    server_mes = server_x_bytes + server_y_bytes
    sigVer(server_h, server_s, IKey_Ser, server_mes)

def Reset_SPK():
    global IK_Pri
    h_reset, s_reset = sigGen(stuID, IK_Pri)
    ResetSPK(h_reset, s_reset)

# 2.3 ------------------------------------------------------------------------------------------------------

def KHMACGen(m):
    global SPK_Pri, server_pub
    T = SPK_Pri * server_pub
    T_x_bytes = T.x.to_bytes(length = (T.x.bit_length()+7) // 8 , byteorder = 'big')
    T_y_bytes = T.y.to_bytes(length = (T.y.bit_length()+7) // 8 , byteorder = 'big')
    U = T_x_bytes + T_y_bytes + m
    h = SHA3_256.new(U)
    h_bytes = int.from_bytes(h.digest() , 'big') % n
    KHMAC = h_bytes.to_bytes(length = (h_bytes.bit_length()+7) // 8 , byteorder = 'big')
    return KHMAC

def OTKGen():
    m = b'NoNeedToRideAndHide'
    KHMAC = KHMACGen(m)
    OTKs = []
    HMACs = []

    for i in range(0,10):
        pri, pub = keyGen()
        OTKs.append((pri, pub))

        pub_x_bytes = pub.x.to_bytes(length = (pub.x.bit_length()+7) // 8 , byteorder = 'big')
        pub_y_bytes = pub.y.to_bytes(length = (pub.y.bit_length()+7) // 8 , byteorder = 'big')

        h = HMAC.new(msg = pub_x_bytes + pub_y_bytes , digestmod = SHA256, key = KHMAC)
        h = h.hexdigest()
        HMACs.append(h)

    return OTKs, HMACs

def Register_OTK():
    global SPK_Pri, server_pub, OTKs_Pri, OTKs_last_id
    OTKs, HMACs = OTKGen()

    for i in range(0,10):
        res = OTKReg(OTKs_last_id + i,OTKs[i][1].x,OTKs[i][1].y,HMACs[i])
        OTKs_Pri[i] = OTKs[i][0]
        if res == True:
            WriteToFile(i+7, OTKs[i][0])

    OTKs_last_id = 9
    WriteToFile(17, OTKs_last_id)

def Reset_OTK():
    global IK_Pri, OTKs_last_id
    h_reset, s_reset = sigGen(stuID, IK_Pri)
    ResetOTK(h_reset, s_reset)
    OTKs_last_id = 0
    WriteToFile(17, OTKs_last_id)

# 3.1 ------------------------------------------------------------------------------------------------------

def SessionKeyGen(OTKID, EK_Pub):
    global OTKs_Pri

    T = OTKs_Pri[OTKID % 10] * EK_Pub

    T_x_bytes = T.x.to_bytes(length = (T.x.bit_length()+7) // 8 , byteorder = 'big')
    T_y_bytes = T.y.to_bytes(length = (T.y.bit_length()+7) // 8 , byteorder = 'big')
    U = T_x_bytes + T_y_bytes + b'MadMadWorld'

    Session_hash = SHA3_256.new(U)
    Session_int = int.from_bytes(Session_hash.digest() , 'big') % n
    Session_Key = Session_int.to_bytes(length = (Session_int.bit_length()+7) // 8 , byteorder = 'big')

    return Session_Key

def SessionKeyGenSender(OTK_Pub, EK_Pri):
    T = OTK_Pub * EK_Pri

    T_x_bytes = T.x.to_bytes(length = (T.x.bit_length()+7) // 8 , byteorder = 'big')
    T_y_bytes = T.y.to_bytes(length = (T.y.bit_length()+7) // 8 , byteorder = 'big')
    U = T_x_bytes + T_y_bytes + b'MadMadWorld'

    Session_hash = SHA3_256.new(U)
    Session_int = int.from_bytes(Session_hash.digest() , 'big') % n
    Session_Key = Session_int.to_bytes(length = (Session_int.bit_length()+7) // 8 , byteorder = 'big')

    return Session_Key

def KeyDerivationChain(KDF_Key_In, iterNo):
    ENC_hash = SHA3_256.new(KDF_Key_In + b'LeaveMeAlone')
    ENC_int = int.from_bytes(ENC_hash.digest() , 'big') % n

    ENC_Key = ENC_int.to_bytes(length = (ENC_int.bit_length()+7) // 8 , byteorder = 'big')

    HMAC_hash = SHA3_256.new(ENC_Key + b'GlovesAndSteeringWheel')
    HMAC_int = int.from_bytes(HMAC_hash.digest() , 'big') % n

    HMAC_Key = HMAC_int.to_bytes(length = (HMAC_int.bit_length()+7) // 8 , byteorder = 'big')

    KDF_hash = SHA3_256.new(HMAC_Key + b'YouWillNotHaveTheDrink')
    KDF_int = int.from_bytes(KDF_hash.digest() , 'big') % n

    KDF_Key = KDF_int.to_bytes(length = (KDF_int.bit_length()+7) // 8 , byteorder = 'big')

    if iterNo == 1:
        return ENC_Key, HMAC_Key

    return KeyDerivationChain(KDF_Key, iterNo - 1)

# 3.2 ------------------------------------------------------------------------------------------------------

def RequestMessage():
    global IK_Pri, E
    h, s = sigGen(stuID, IK_Pri)
    res = ReqMsg(h, s)
    return res

# 3.3 ------------------------------------------------------------------------------------------------------

def DecryptMessage(Sender_ID, OTKID, MSGID, MSG, EK_Pub):
    global OTKs_Pri

    Session_Key = SessionKeyGen(OTKID, EK_Pub)

    ENC_Key, HMAC_Key = KeyDerivationChain(Session_Key, MSGID)

    nonce = MSG[:8]
    ct = MSG[8:]
    message_hmac = MSG[-32:]

    calculated_hash = HMAC.new(msg = MSG[8:-32] , digestmod = SHA256, key = HMAC_Key)
    calculated_hash_int = int.from_bytes(calculated_hash.digest() , 'big') % n
    calculated_hmac = calculated_hash_int.to_bytes(length = (calculated_hash_int.bit_length()+7) // 8 , byteorder = 'big')
    
    if(calculated_hmac == message_hmac):
        print("\nHMAC Verified!")
        cipher = AES.new(ENC_Key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        message = str(pt[:-32])[2:-1]
        print("\nYou got message \" {} \" from user with ID {}.".format(message, Sender_ID))
        return message
    else:
        print("HMAC Not Verified!")
        return "INVALIDHMAC"

def RequestCheckMessage():
    res = RequestMessage()
    try:
        Sender_ID, OTKID, MSGID, MSG_int, EK_X, EK_Y = res[0], res[1], res[2], res[3], res[4], res[5]

        MSG = MSG_int.to_bytes(length = (MSG_int.bit_length()+7) // 8 , byteorder = 'big')
        EK_Pub = Point(EK_X, EK_Y, E)

        message = DecryptMessage(Sender_ID, OTKID, MSGID, MSG, EK_Pub)
        return message

    except:
        print("\nNo messages in the Inbox!")
        return "No_Messages"

# 4.1 ------------------------------------------------------------------------------------------------------

def GetReceiverInfo(RCVID):
    global IK_Pri
    h, s = sigGen(RCVID, IK_Pri)
    res = reqOTKB(stuID, RCVID, h, s)
    return res

def EncryptMessage(MSG, ENC_Key, HMAC_Key):
    message = bytes(MSG, 'utf-8')
    
    cipher = AES.new(ENC_Key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(message)
    nonce = cipher.nonce
    calculated_hash = HMAC.new(msg = ct_bytes , digestmod = SHA256, key = HMAC_Key)
    calculated_hash_int = int.from_bytes(calculated_hash.digest() , 'big') % n
    hmac = calculated_hash_int.to_bytes(length = (calculated_hash_int.bit_length()+7) // 8 , byteorder = 'big')

    data = nonce + ct_bytes + hmac

    ct_message = int.from_bytes(data , 'big')

    return ct_message


def sendMessages(rcvID, MSG_List):

    if len(MSG_List) != 0:
        res = GetReceiverInfo(rcvID)
        RCV_OTKID, RCV_OTK_X, RCV_OTK_Y = res[0], res[1], res[2]
        EK_Pri, EK_Pub = keyGen()
        OTK_Pub = Point(RCV_OTK_X, RCV_OTK_Y, E)

    for i in range(len(MSG_List)):
        MSGID = i + 1
        MSG = MSG_List[i]
        Session_Key = SessionKeyGenSender(OTK_Pub, EK_Pri)
        ENC_Key, HMAC_Key = KeyDerivationChain(Session_Key, MSGID)

        ct_message = EncryptMessage(MSG, ENC_Key, HMAC_Key)
        
        SendMsg(stuID, rcvID, RCV_OTKID, MSGID, ct_message, EK_Pub.x, EK_Pub.y)

# 4.2 ------------------------------------------------------------------------------------------------------    

def statusControl():
    global IK_Pri
    h, s = sigGen(stuID, IK_Pri)
    num_of_messages , remaining_OTKs, status_of_messages = Status(stuID, h, s)
    neededOTK = 10 - remaining_OTKs
    return num_of_messages, neededOTK

def augmented_Register_OTK(neededOTK):
    global SPK_Pri, server_pub, OTKs_Pri, OTKs_last_id
    OTKs, HMACs = OTKGen()

    for i in range(0, neededOTK):
        res = OTKReg(OTKs_last_id + (i + 1), OTKs[i][1].x, OTKs[i][1].y, HMACs[i])
        OTKs_Pri[i] = OTKs[i][0]
        if res == True:
            WriteToFile(((OTKs_last_id + (i + 1)) % 10) + 7, OTKs[i][0])

    OTKs_last_id += neededOTK
    WriteToFile(17, OTKs_last_id)

# Menu -----------------------------------------------------------------------------------------------------

menu_main_options = {
    1: 'Key Generation and Registering to the Server',
    2: 'Send / Receive Messages',
    3: 'Exit',
}

menu_1_options = {
    1: 'Register IK',
    2: 'Authenticate IK',
    3: 'Reset IK',
    4: 'Register SPK and Validate Server SPK',
    5: 'Reset SPK',
    6: 'Register OTK',
    7: 'Reset OTK',
    8: 'Print Global Variables',
    9: 'Exit to Main Menu',
}

menu_2_options = {
    1: 'Send Messages',
    2: 'Request Message and Check',
    3: 'Register Missing OTKs',
    4: 'Control Status',
    5: 'Exit to Main Menu',
}

menu_send_options = {
    1: 'Write a Message',
    2: 'Send Messages',
}

def print_menu(menuNo):
    print("\nPlease choose an option:")
    if menuNo == 0:
        for key in menu_main_options.keys():
            print (key, '--', menu_main_options[key])
    elif menuNo == 1:
        for key in menu_1_options.keys():
            print (key, '--', menu_1_options[key])
    elif menuNo == 2:
        for key in menu_2_options.keys():
            print (key, '--', menu_2_options[key])
    elif menuNo == 3:
        for key in menu_send_options.keys():
            print (key, '--', menu_send_options[key])

if __name__=='__main__':
    with open('client_info.txt', 'w') as file:
        file.writelines(data)
    while(True):
        print_menu(0)
        option_main = ''
        try:
            option_main = int(input('Enter your choice: '))
        except:
            print('Wrong input. Please enter a number ...')
        if option_main == 1:
            menu_1 = True
            stuID = int(input('Enter your ID: '))
            WriteToFile(0, stuID)
            while(menu_1):
                print_menu(1)
                option = ''
                try:
                    option = int(input('Enter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')
                if option == 1:
                    Register_IK()
                elif option == 2:
                    auth_code = int(input('Enter verification code: '))
                    WriteToFile(2, auth_code)
                    Authenticate_IK(auth_code)
                elif option == 3:
                    rcode = int(input('Enter reset code: '))
                    WriteToFile(3, rcode)
                    Reset_IK(rcode)
                elif option == 4:
                    Register_Validate_SPK()
                elif option == 5:
                    Reset_SPK()
                elif option == 6:
                    Register_OTK()
                elif option == 7:
                    Reset_OTK()
                elif option == 8:
                    print("Student ID: ", stuID)
                    print("IK Private: ", IK_Pri)
                    print("IK Public: ", IK_Pub)
                    print("IK Verification Code: ", auth_code)
                    print("IK Reset Code: ", rcode)
                    print("SPK Private: ", SPK_Pri)
                    print("SPK Public: ", SPK_Pub)
                    print("Server SPK Public: ", server_pub)
                elif option == 9:
                    menu_1 = False
                else:
                    print('Invalid option. Please enter a number between 1 and 8 !')
        elif option_main == 2:
            menu_2 = True
            status_checked = False
            numOTKs = 0
            num_of_messages = 1
            while(menu_2):
                print_menu(2)
                option = ''
                try:
                    option = int(input('Enter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')
                if option == 1:
                    RCVID = int(input('Enter Receiver ID: '))
                    MSG_List = []
                    menu_send = True
                    while(menu_send):
                        print_menu(3)
                        option_send = ''
                        try:
                            option_send = int(input('Enter your choice: '))
                        except:
                            print('Wrong input. Please enter a number ...')
                        if option_send == 1:
                            MSG = str(input('Enter Your Message: '))
                            MSG_List.append(MSG)
                        elif option_send == 2:
                            sendMessages(RCVID, MSG_List)
                            menu_send = False
                elif option == 2:
                    msg = RequestCheckMessage()
                elif option == 3:
                    if status_checked == True:
                        if num_of_messages == 0:
                            augmented_Register_OTK(numOTKs)
                            status_checked = False
                        else:
                            print("The OTKs cannot be replaced until all messages in the inbox are read!")
                    else:
                        print("\nPlease first check your status!")
                elif option == 4:
                    num_of_messages, numOTKs = statusControl()
                    status_checked = True
                elif option == 5:
                    menu_2 = False
                else:
                    print('Invalid option. Please enter a number between 1 and 3 !')
        elif option_main == 3:
            print('Terminating...')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 3.')