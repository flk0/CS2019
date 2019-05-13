####################
### 1. Decode Data
####################

# Analog data encoding
first_zero = b"\xff"*10+b"\x00"*8
zero = b"\xff"*8+b"\x00"*8
first_one = b"\xff"*18+b"\x00"*16
one = b"\xff"*16+b"\x00"*16
corrupted = b"\x11"*400

with open('/home/flk/Working/CyberSkills2019/Dev/Army CTF Challenge/corrupted-tape-666.WAV','rb') as f:
    txt = f.read()
    
block = txt[0xE0532:0x3A3974]
checksum = txt[0x3A3974:0x3A3A44]

# Ugly code to quickly get 'before' and 'after' block chunks
pieces = block.split(b'\x11')
blockChunks = [pieces[0], pieces[400]]

def decodeBits(block):
    decoded = ''
    counter = 0
    firstZeroDone=False
    firstOneDone=False
    while counter < len(block):
        if block[counter:counter+len(first_zero)] == first_zero:
            if firstZeroDone:
                print('Parsing fail (extra first zero) at '+hex(counter))
                return None
            firstZeroDone = True
            decoded += '0'
            counter += len(first_zero)
        elif block[counter:counter+len(zero)] == zero:
            decoded += '0'
            counter += len(zero)
        elif block[counter:counter+len(first_one)] == first_one:
            if firstOneDone:
                print('Parsing fail (extra first one) at '+hex(counter))
                return None
            firstOneDone = True
            decoded += '1'
            counter += len(first_one)
        elif block[counter:counter+len(one)] == one:
            decoded += '1'
            counter += len(one)
        elif block[counter:counter+len(corrupted)] == corrupted:
            decoded += ''
            counter += len(corrupted)
        else:
            print('Parsing fail at '+hex(counter))
            return None
    return decoded

# Analog to bitstream
decodedBlockBitstreams = [decodeBits(i) for i in blockChunks]
decodedChecksumBitstream = decodeBits(checksum)

def decodeBytes(bits):
    bytestream = b""
    checksum = 0x00
    for byte in list(map(''.join, zip(*[iter(bits)]*8))):
        value = int(byte[1:]+byte[0],2)
        bytestream += value.to_bytes(1,'big')
        checksum ^= value
    return {'data': bytestream,'checksum': checksum}

blockBytes = [decodeBytes(i) for i in decodedBlockBitstreams]
checksumBytes = decodeBytes(decodedChecksumBitstream)['checksum']


####################
### 2. Recover Missing Bytes
####################

# First missing byte = Given checksum ^ Computed checksum of first block chunk

givenPartialChecksum = 0xB2
firstMissingByte = (blockBytes[0]['checksum'] ^ 0xB2).to_bytes(1,'big')

# Test for second missing byte.
# Total checksum = Checksum(first block chunk+missing first byte) ^ Checksum(second missing byte (if any)) ^ Checksum(second block chunk)
# -> Checksum(second missing byte (if any)) = Total checksum ^ Checksum(first block chunk+missing first byte) ^ Checksum(second block chunk)

embeddedTotalChecksum = checksumBytes ^ 0xBB
secondMissingByte = embeddedTotalChecksum ^ givenPartialChecksum ^ blockBytes[1]['checksum']
assert(secondMissingByte != 0)
secondMissingByte = secondMissingByte.to_bytes(1,'big')



####################
### 3. Encode New Data
####################

def encodeByte(byte):
    output = b""
    stream = bin(ord(byte))[2:]
    # front pad
    stream = '0'*(8-len(stream))+stream
    
    # right shift
    stream = stream[7] + stream[:7]
    
    for i in stream:
        if i == '1':
            output += one
        elif i == '0':
            output += zero
        else:
            print('Error')
            return None
    return output

missingBlockChunk = encodeByte(firstMissingByte) + encodeByte(secondMissingByte)

# Data size has changed -> need to fix RIFF data size element.
# Original size 'BE C9 9F 00' at byte 40

sizeCorrection = (0xBE - 400 + len(missingBlockChunk)).to_bytes(1,'big')

fixedWAV = txt.replace(corrupted,missingBlockChunk)
fixedWAV = fixedWAV[:40] + sizeCorrection + fixedWAV[41:]
with open('/home/flk/Working/CyberSkills2019/Dev/Army CTF Challenge/fix.WAV','wb') as f:
    f.write(fixedWAV)


# $ wine openmsx.exe tapeloader.rom -cassetteplayer fix.WAV
    
    

