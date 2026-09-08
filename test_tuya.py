import tinytuya
 
tinytuya.set_debug(True)
 
LOCAL_KEY = 'Q;SGIxCix&WFwJGy'
 
print("--- debug crudo, protocolo 3.5 ---")
d = tinytuya.Device('eba40c3bb8205604f1mzip', '192.168.1.137', LOCAL_KEY, version=3.5)
print(d.status())