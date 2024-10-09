p4 = bfrt.counter_example.pipe
counter = p4.SwitchIngress.counter

for i in range(16):
    counter.get(REGISTER_INDEX=i, from_hw=True)

counter.info()
bfrt.complete_operations()  
