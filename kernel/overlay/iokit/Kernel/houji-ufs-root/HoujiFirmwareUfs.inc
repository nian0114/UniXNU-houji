// SPDX-License-Identifier: BSD-2-Clause-Patent
// Only the ADSP worker enters this path, after normal UFS/GPU coexistence is
// qualified. The live stock layout places modem_a on UFS LUN 4. No write API,
// alternate-slot fallback or fixed personal GPT identifiers are used here.
#include "battery/HoujiFirmware.h"
#include "battery/HoujiFirmwareGpt.h"
static HoujiFirmwarePartition gHoujiModem;
static unsigned gHoujiModemStage;
static uint32_t gHoujiModemResult,gHoujiModemSense;
static IOLock *gHoujiModemLock;
static IOLock *houjiModemLock(void) {
    IOLock *l=__atomic_load_n(&gHoujiModemLock,__ATOMIC_ACQUIRE);
    if(l)return l;
    IOLock *c=IOLockAlloc();if(!c)return nullptr;
    if(!__atomic_compare_exchange_n(&gHoujiModemLock,&l,c,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        IOLockFree(c);return l;
    }
    return c;
}
extern "C" void houji_modem_status(unsigned *stage,uint32_t *result,uint32_t *sense) {
    // Same worker as the reader, copied into an immutable diagnostic phase.
    *stage=gHoujiModemStage;*result=gHoujiModemResult;*sense=gHoujiModemSense;
}
static IOReturn houjiFirmwareTransfer(const HoujiFirmwareReadGrant &grant,uint64_t lba,
                                    uint32_t blocks,void *to) {
    if(blocks>32 || lba>0xffffffffULL || (blocks && (!to || lba>0xffffffffULL-(blocks-1))))
        return kIOReturnBadArgument;
    uint8_t cdb[10]={};
    if(blocks) {
        cdb[0]=0x28;cdb[2]=uint8_t(lba>>24);cdb[3]=uint8_t(lba>>16);
        cdb[4]=uint8_t(lba>>8);cdb[5]=uint8_t(lba);cdb[7]=uint8_t(blocks>>8);cdb[8]=uint8_t(blocks);
    }
    uint32_t scsi=0;IOLockLock(gHost.lock);
    gFirmwareReadGrant=grant;
    IOReturn status=hostScsi(4,cdb,blocks?10:6,blocks!=0,blocks*4096,1000000,&scsi);
    if(status==kIOReturnSuccess && blocks)memcpy(to,gHost.virt+kDataOffset,blocks*4096);
    gHoujiModemResult=static_cast<uint32_t>(status);gHoujiModemSense=gRootDiagnostic.sense;
    gFirmwareReadGrant={};
    IOLockUnlock(gHost.lock);return status;
}
extern "C" int houji_modem_partition(uint64_t *blocks) {
    IOLock *lock=houjiModemLock();if(!lock)return 0;
    IOLockLock(lock);
    gHoujiModemStage=1;
    if(!blocks || !gHost.ready || gHost.poisoned || !houjiNativeGpuFsAllowed()){IOLockUnlock(lock);return 0;}
    if(gHoujiModem.blocks){*blocks=gHoujiModem.blocks;IOLockUnlock(lock);return 1;}
    bool ready=false;
    gHoujiModemStage=2;const HoujiFirmwareReadGrant metadata={1,0,0};
    for(unsigned i=0;i<3 && !ready;i++) {
        ready=houjiFirmwareTransfer(metadata,0,0,nullptr)==kIOReturnSuccess;
        if(gHost.poisoned){IOLockUnlock(lock);return 0;}
        if(!ready)IOSleep(20);
    }
    if(!ready){IOLockUnlock(lock);return 0;}
    // These buffers are serialized by gHoujiModemLock, not a 20 KiB kernel stack frame.
    static uint8_t header[4096],entries[16384],again[4096];
    gHoujiModemStage=3;
    if(houjiFirmwareTransfer(metadata,1,1,header)!=kIOReturnSuccess){IOLockUnlock(lock);return 0;}
    gHoujiModemStage=4;
    uint32_t bytes=houji_fw_gpt_bytes(header,sizeof(header));
    if(!bytes){IOLockUnlock(lock);return 0;}
    gHoujiModemStage=5;
    if(houjiFirmwareTransfer(metadata,2,(bytes+4095)/4096,entries)!=kIOReturnSuccess){IOLockUnlock(lock);return 0;}
    gHoujiModemStage=6;
    HoujiFirmwarePartition part={};
    if(!houji_fw_gpt_partition(header,entries,bytes,&part)){IOLockUnlock(lock);return 0;}
    gHoujiModemStage=7;
    if(houjiFirmwareTransfer(metadata,1,1,again)!=kIOReturnSuccess || memcmp(header,again,sizeof(header))){IOLockUnlock(lock);return 0;}
    gHoujiModem=part;*blocks=part.blocks;gHoujiModemStage=8;
    IOLockUnlock(lock);return 1;
}
extern "C" int houji_modem_read(uint64_t lba,uint32_t blocks,void *to) {
    if(!gHoujiModem.blocks || !to || !blocks || blocks>32 ||
       lba>=gHoujiModem.blocks || blocks>gHoujiModem.blocks-lba)return 0;
    const HoujiFirmwareReadGrant grant={2,gHoujiModem.first,gHoujiModem.blocks};
    return houjiFirmwareTransfer(grant,gHoujiModem.first+lba,blocks,to)==kIOReturnSuccess;
}
