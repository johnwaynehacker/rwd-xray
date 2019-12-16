## Make a rwd that enable steering down to 0mph on honda cars 

### Supported car models
- CR-V 5G (Tested by joe1)
- Civic (eps motor part number 39990-TBA), Untested.
- Civic (eps motor part number 39990-TEA), Untested.

### How to remove the 25mph steering limitation in the firmware code (credits to goehot, greg, joe1, leycera)
- CR-V 5g
![](https://i.ibb.co/ZXncZS8/image.png)
![](https://i.ibb.co/grytxpc/image.png)
- Civic 39990-TBA
![](https://i.ibb.co/KycgW3Y/image.png)
![](https://i.ibb.co/3cvL9cG/image.png)

- "00 28" is the lowest speed that eps can accept steering request at. 
- So the limitation can be removed by changing "00 28" to "00 00", make a rwd patch, flash it to the car. 

### The problem for making the rwd patch
- Both CR-V and civic use [rwd format 0x5A](https://github.com/gregjhogan/rwd-xray/blob/master/format/x5a.py)
- Most rwd params can be found from parsing stock rwd using [rwd-xray.py](https://github.com/gregjhogan/rwd-xray/blob/master/rwd-xray.py), except the encryption algorithm.
- The code in rwd is encrypted using a byte substitution algo, firmware will decrypt the code inplace.
- The encryption algorithm may vary for every honda model.

### How we found the encryption algorithm for civic 39990-TBA
- We have a working homemade CR-V rwd and we also have the corresponding full firmware bin dumped from the eps motor.
- We extracted encrypted code block from the rwd and save it to file.
- We also extract the original code from the full fw bin and save to to file (from offset 0x4000 to 0x6C000).
- Then we tried building a byte-to-byte map from these two files using [this tool](https://github.com/nanamiwang/rwd-xray/blob/master/tools/build-byte-lookup-table.py).
```
python3 build-byte-lookup-table.py --input_bin ~/data/crv_5g_stock.bin --input_enc ~/data/2017-honda-crv-eps.enc
```
- We got a one-to-one map between encrypted and decrypted code, so apparently it is a correct byte lookup table for encryption. [The table here](https://github.com/nanamiwang/rwd-xray/blob/80600d071dc580db727a96c9b83c9615058bcf7b/tools/bin_to_rwd.py#L16)
- We have a full eps firmware bin dumped from civic 39990-TBA, also the corresponding stock rwd from i-HDS 1.004 installation package (You can find the package by googling) 
- So we tried decrypting the code from civic rwd using the CR-V lookup table, it worked, the decrypted code totally match with the civic full firmware bin. So we have a conclusion that civic uses the same encryption algo as CR-V.

### Patch the code and make the rwd
- Patch the full firmware bin
  - A hex editor is ok for this job
  - Open the CR-V or civic full firmware bin
  - Find "00 28 01 90" in the bin, modify "28" to "00", then save it.
- Convert the bin to rwd using [bin_to_rwd.py](https://github.com/nanamiwang/rwd-xray/blob/master/tools/bin_to_rwd.py)
  - CR-V
```
nanami@nanami-To-be-filled-by-O-E-M:~/rwd-xray/tools$ python3 bin_to_rwd.py --input_bin ~/data/crv_5g_user_patched.bin
Creating rwd for model 39990-TLA-A030
Update checksum at offset 0x6bf80 from 0x419b to 0x4173
Update checksum at offset 0x6bffe from 0x24ef to 0x253f
Encryption done, saved to /home/nanami/data/crv_5g_user_patched.bin.enc.
[0]: ['\x00']
[1]: []
[2]: ['0']
[3]: ['39990-TLA-A030\x00\x00', '39990-TLA-A040\x00\x00']
[4]: ['\x01\x11\x01\x12\x11 ', '\x01\x11\x01\x12\x11 ']
[5]: ['\x01\x02\x03']
start = 0x4000 len = 0x6c000
file checksum: 0x38c2342
done!
RWD file /home/nanami/data/crv_5g_user_patched.bin.rwd created.
```
  - Civic 39990-TBA
```
nanami@nanami-To-be-filled-by-O-E-M:~/rwd-xray/tools$ python3 bin_to_rwd.py --input_bin ~/data/civic_tba_0_steering.bin --model 39990-TBA-A030
Creating rwd for model 39990-TBA-A030
Update checksum at offset 0x4bf80 from 0xdd23 to 0xdcfb
Update checksum at offset 0x4bffe from 0xeddf to 0xee2f
Encryption done, saved to /home/nanami/data/civic_tba_0_steering.bin.enc.
[0]: ['\x00']
[1]: []
[2]: ['\x03']
[3]: ['39990-TBA-A000\x00\x00', '39990-TBA-A010\x00\x00', '39990-TBA-A020\x00\x00', '39990-TBA-A030\x00\x00']
[4]: ['\x00\x11\x00\x12\x10 ', '\x00\x11\x00\x12\x10 ', '\x01\x11\x01\x12\x11 ', '\x01\x11\x01\x12\x11 ']
[5]: ['\x01\x02\x03']
start = 0x4000 len = 0x4c000
file checksum: 0x28afc56
done!
RWD file /home/nanami/data/civic_tba_0_steering.bin.rwd created.
```

### To be safe, verify the rwd, make sure we are making the correct modifications
- Compare our homemade rwd with the stock rwd
  - The speed low byte is changed from 0x28 to 0x0
![](https://i.ibb.co/H76yd0F/image.png)
```
>>> hex(decrypt_lookup_table[0x71])
'0x0'
>>> hex(decrypt_lookup_table[0x10])
'0x28'
```
  - The block checksum, padded block checksum, rwd file checksum are updated correctly.

### How to test the rwd on car
- Try the stock rwd first, flash it to your car. If it is working, your car is compatible with the 0 steering rwd.
- Then try flashing the homemade 0 steering rwd.
- If the homemade rwd bricks the eps, use stock rwd to do recovery.
- <b>Caution! Improper flashing may damage the eps. I don't have civic, so I never test it on car. Use it at your own risk.</b>
### The files
 - [Civic stock rwd](https://github.com/nanamiwang/rwd-xray/raw/master/tools/files/39990-TBA-A030-M1.rwd.gz)
 - [Civic 39990-TBA 0 steering rwd](https://github.com/nanamiwang/rwd-xray/raw/master/tools/files/civic_tba_0_steering.bin.rwd)
