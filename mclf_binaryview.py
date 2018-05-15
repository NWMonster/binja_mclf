# MCLF format loader
# By NWMonster

from binaryninja import *
from binaryninja.log import log_info, log_error
import traceback
import struct

class RunInBackground(BackgroundTaskThread):
    def __init__(self, bv, msg, func):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv
        self.func = func

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        self.func()
        bv.commit_undo_actions()
        bv.update_analysis()

class MCLFView(BinaryView):

    name = "MCLF"
    long_name = "MCLF"
    entry_point = 0
    mclf_header_struct = 0
    text_header_struct = 0

    # https://github.com/Trustonic/trustonic-tee-user-space/blob/master/common/MobiCore/inc/mcLoadFormat.h

    MCLF_HEADER_MAGIC       = "MCLF"
    MCLF_HEADER_SIZE_V1     = 72
    MCLF_HEADER_SIZE_V2     = 76
    MCLF_HEADER_SIZE_V23    = 96
    MCLF_TEXT_INFO_OFFSET   = 128
    MCLF_TEXT_INFO_SIZE     = 36
    MCLF_HEADER_SIZE        = MCLF_TEXT_INFO_OFFSET + MCLF_TEXT_INFO_SIZE
    tlApiLibEntry           = 0x108C

    MC_SERVICE_HEADER_FLAGS_PERMANENT               = (1 << 0) #/**< Loaded service cannot be unloaded from MobiCore. */
    MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE    = (1 << 1) #/**< Service has no WSM control interface. */
    MC_SERVICE_HEADER_FLAGS_DEBUGGABLE              = (1 << 2) #/**< Service can be debugged. */
    MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT         = (1 << 3) #/**< New-layout trusted application or trusted driver. */

    memType_l = [
    'MCLF_MEM_TYPE_INTERNAL_PREFERRED', # = 0, /**< If available use internal memory; otherwise external memory. */
    'MCLF_MEM_TYPE_INTERNAL',           # = 1, /**< Internal memory must be used for executing the service. */
    'MCLF_MEM_TYPE_EXTERNAL',           # = 2, /**< External memory must be used for executing the service. */
    ]

    serviceType_l = [
    'SERVICE_TYPE_ILLEGAL',         #= 0, /**< Service type is invalid. */
    'SERVICE_TYPE_DRIVER',          #= 1, /**< Service is a driver. */
    'SERVICE_TYPE_SP_TRUSTLET',     #= 2, /**< Service is a Trustlet. */
    'SERVICE_TYPE_SYSTEM_TRUSTLET', #= 3, /**< Service is a system Trustlet. */
    'SERVICE_TYPE_MIDDLEWARE',      #= 4, /**< Service is a middleware. */
    'SERVICE_TYPE_LAST_ENTRY',      #= 5, /**< marker for last entry */
    ]

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)

    @classmethod
    def is_valid_for_data(self, data):
        magic = data.read(0x0, 4)
        if magic != 'MCLF':
            return False
        Major = data.read(0x6, 2)
        if Major != '\x02\x00':
            return False
        return True


    def init_sboot(self):
        try:
            mclf_header = types.Structure()
            mclf_header.append(Type.array(Type.int(1, None, "char"), 4), 'magic')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'version')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'flags')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'memType')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'serviceType')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'numInstances')
            mclf_header.append(Type.array(Type.int(1, None, "char"), 16), 'uuid')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'driverId')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'numThreads')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'textVA')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'textLen')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'dataVA')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'dataLen')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'bssLen')
            mclf_header.append(Type.int(4, None, "uint32_t"), 'entry')

            text_header = types.Structure()
            text_header.append(Type.int(4, None, "uint32_t"), 'version')
            text_header.append(Type.int(4, None, "uint32_t"), 'HeaderLen')
            text_header.append(Type.int(4, None, "uint32_t"), 'requiredFeat')
            text_header.append(Type.int(4, None, "uint32_t"), 'mcLib_start')
            text_header.append(Type.int(4, None, "uint32_t"), 'mcLib_len')
            text_header.append(Type.int(4, None, "uint32_t"), 'mcLibBase')
            text_header.append(Type.int(4, None, "uint32_t"), 'tlApiVers')
            text_header.append(Type.int(4, None, "uint32_t"), 'drApiVers')
            text_header.append(Type.int(4, None, "uint32_t"), 'ta_properties')

            with open(self.file.filename, 'rb') as f:
                # mclf header
                f.seek(0)
                magic           = f.read(4);
                version         = struct.unpack("<I", f.read(4))[0];
                flags           = struct.unpack("<I", f.read(4))[0];
                memType         = struct.unpack("<I", f.read(4))[0];
                serviceType     = struct.unpack("<I", f.read(4))[0];
                numInstances    = struct.unpack("<I", f.read(4))[0];
                uuid            = struct.unpack("<IIII", f.read(16));
                driverId        = struct.unpack("<I", f.read(4))[0];
                numThreads      = struct.unpack("<I", f.read(4))[0];
                textVA          = struct.unpack("<I", f.read(4))[0];
                textLen         = struct.unpack("<I", f.read(4))[0];
                dataVA          = struct.unpack("<I", f.read(4))[0];
                dataLen         = struct.unpack("<I", f.read(4))[0];
                bssLen          = struct.unpack("<I", f.read(4))[0];
                entry           = struct.unpack("<I", f.read(4))[0];
                version = str((version)>>16) + "." + str((version)&0xff)
                if version == "2.3" or version == "2.4":
                    sipId                = struct.unpack("<I", f.read(4))[0];
                    suidData             = struct.unpack("<III", f.read(12))[0];
                    permittedHwCfg       = struct.unpack("<I", f.read(4))[0];
                    mclf_header.append(Type.int(4, None, "uint32_t"), 'sipId')
                    mclf_header.append(Type.array(Type.int(1, None, "char"), 12), 'suidData')
                    mclf_header.append(Type.int(4, None, "uint32_t"), 'permittedHwCfg')
                if version == "2.4":
                    gp_level             = struct.unpack("<I", f.read(4))[0];
                    attestationOffset    = struct.unpack("<I", f.read(4))[0];
                    mclf_header.append(Type.int(4, None, "uint32_t"), 'gp_level')
                    mclf_header.append(Type.int(4, None, "uint32_t"), 'attestationOffset')
                
                # text header
                f.seek(self.MCLF_TEXT_INFO_OFFSET)
                text_version    = struct.unpack("<I", f.read(4))[0];
                textHeaderLen   = struct.unpack("<I", f.read(4))[0];
                requiredFeat    = struct.unpack("<I", f.read(4))[0];
                mcLib_start     = struct.unpack("<I", f.read(4))[0];
                mcLib_len       = struct.unpack("<I", f.read(4))[0]; 
                mcLibBase       = struct.unpack("<I", f.read(4))[0];
                tlApiVers       = struct.unpack("<I", f.read(4))[0];
                drApiVers       = struct.unpack("<I", f.read(4))[0];
                ta_properties   = struct.unpack("<I", f.read(4))[0];
                text_version = str((text_version)>>16) + "." + str((text_version)&0xff)

            self.define_user_type('mclf_header', Type.structure_type(mclf_header))
            self.define_user_type('text_header', Type.structure_type(text_header))

            self.define_user_data_var(textVA, self.get_type_by_name('mclf_header'))
            self.define_user_data_var(textVA + self.MCLF_TEXT_INFO_OFFSET, self.get_type_by_name('text_header'))

            print("MCLF Info:")
            print("\tversion:       " + version)
            print("\tflags:        " +
                " PERMANENT" if flags & self.MC_SERVICE_HEADER_FLAGS_PERMANENT else "" +
                " NO_CONTROL_INTERFACE" if flags & self.MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE else "" +
                " DEBUGGABLE" if flags & self.MC_SERVICE_HEADER_FLAGS_DEBUGGABLE else "" +
                " EXTENDED_LAYOUT" if flags & self.MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT else "")
            print("\tmemType:       " + self.memType_l[memType])
            print("\tserviceType:   " + self.serviceType_l[serviceType])
            print("\tnumInstances:  " + str(numInstances))
            print("\tuuid:          " + str(uuid))
            print("\tdriverId:      " + str(driverId))
            print("\tnumThreads:    " + str(numThreads))
            print("\ttextVA:        " + hex(textVA))
            print("\ttextLen:       " + hex(textLen))
            print("\tdataVA:        " + hex(dataVA))
            print("\tdataLen:       " + hex(dataLen))
            print("\tbssLen:        " + hex(bssLen))
            print("\tentry:         " + hex(entry))
            if version == "2.3" or version == "2.4":
                print("\tsipId:         " + hex(sipId))
                print("\tsuidData:      " + str(suidData))
                print("\tHwCfg:         " + hex(permittedHwCfg))
            if version == "2.4":
                print("\tgp_level:       " + hex(gp_level))
                print("\tattestationOffset: " + hex(attestationOffset))
            print("Text Header Info:")
            print("\ttext_version:  " + text_version)
            print("\textHeaderLen:  " + hex(textHeaderLen))
            print("\trequiredFeat:  " + hex(requiredFeat))
            print("\tmcLib_start:   " + hex(mcLib_start))
            print("\tmcLib_len:     " + hex(mcLib_len))
            print("\tmcLibBase:     " + hex(mcLibBase))
            print("\ttlApiVers:     " + hex(tlApiVers))
            print("\tdrApiVers:     " + hex(drApiVers))
            print("\tta_properties: " + hex(ta_properties))


            flags = 0
            flags |= SegmentFlag.SegmentContainsData
            flags |= SegmentFlag.SegmentContainsCode
            flags |= SegmentFlag.SegmentReadable
            flags |= SegmentFlag.SegmentExecutable

            self.add_user_segment(textVA, textLen, 0, textLen, flags)
            self.add_user_section('.text', textVA, textLen, SectionSemantics.ReadOnlyCodeSectionSemantics)

            self.add_user_segment(dataVA, dataLen, textLen, dataLen, flags & ~SegmentFlag.SegmentContainsCode)
            self.add_user_section('.data', dataVA, dataLen, SectionSemantics.ReadWriteDataSectionSemantics)

            if entry % 4 == 1:
                self.arch = Architecture['thumb2']
                self.platform = Platform['linux-thumb2']
                entry = entry - 1
            else:
                self.arch = Architecture['armv7']
                self.platform = Platform['linux-armv7']

            self.entry_point = entry
            self.add_entry_point(self.entry_point)
            self.create_user_function(self.entry_point)
            self.define_user_symbol(Symbol(enums.SymbolType.FunctionSymbol, entry, 'entry'))
            self.define_user_symbol(Symbol(enums.SymbolType.DataSymbol, textVA, 'mclf_header'))
            self.define_user_symbol(Symbol(enums.SymbolType.DataSymbol, textVA + self.MCLF_TEXT_INFO_OFFSET, 'text_header'))

        except:
            log_error(traceback.format_exc())
            return False

        return True

    def init(self):
        s = RunInBackground(self, "MCLF Loading...", self.init_sboot)
        s.start()
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_point
