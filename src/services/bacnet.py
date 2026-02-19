import asyncio
import BAC0

async def main2():
    my_ip = '192.168.1.96/24'
    bbmdIP = '174.108.199.130:47808'
    bbmdTTL = 900
    bacnet = BAC0.connect(my_ip, bbmdAddress=bbmdIP, bbmdTTL=bbmdTTL) #Connect
    print(bacnet.vendorName)

if __name__ == "__main__":
    asyncio.run(main2())