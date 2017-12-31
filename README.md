# rwd-xray
Honda/Acura calibration file (rwd) firmware extractor

NOTE THAT THIS IS A WORK IN PROGRESS AND MAY NOT OUTPUT VALID FIRMWARE YET

### Usage
From a terminal using python 2.x:  
`./rwd-xray.py ./39990-TV9-A910.rwd.gz`

This will output a file containing the firmware named:  
`39990-TV9-A910.bin`

### What are .rwd files?

Part of the Honda Diagnostic System (HDS) software is a tool to flash firmware updates (J2534 Rewrite application) and a set of firmware update files.

The firmeware update files can be found in the directory:  
`C:\Program Files (x86)\Honda\J2534 Pass Thru\CalibFiles`

Each firmware file is named according to the part number  
(usually found printed on outside of the part)  
`MODULE-VEHICLE-VERSION.rwd.gz`

for example, here is a firmware update for a 2016 Acura ILX EPS module:  
`39990-TV9-A910.rwd.gz`

|   |   |   |
|---|---|---|
|`MODULE`|39990|EPS module|
|`VEHICLE`|TV9|Acura ILX|
|`VERSION`|A910|manufacturer region/code|

## .rwd File Formats
Each file has a signature, headers, and firmware

---

### Z format
##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|S|signature (0x5a)|
|2|←↓|field delimiter (0x0d0a)|

##### HEADERS
```
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
| ...                 |
| (repeat C times)    |
| ...                 |
+-+-+=====+===+-+=====+
|C|L|V...V|...|L|V...V|
+-+-+=====+===+-+=====+
```

|bytes|label|description|
|----:|----:|-----------|
|1|C|number of values in header (can be zero)|
|1|L|length of header value|
|varies|V|header value (length = L)|

##### FIRMWARE
TBD

---

### 1 format
##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|S|signature (0x31)|
|2|←↓|field delimiter (0x0d0a)|

##### HEADERS
```
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
| ...                       |
| (repeat)                  |
| ...                       |
+---+=======+===+=======+---+
|T←↓|V...V←↓|...|V...V←↓|T←↓|
+---+=======+===+=======+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|T|type of header|
|varies|V|header value|
|2|←↓|field delimiter (0x0d0a)|

##### FIRMWARE
```
+----+----------------+
|AAAA|DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
+----+----------------+
| ...                 |
| (repeat)            |
| ...                 |
+----+----------------+
|AAAA|DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
|    |DDDDDDDDDDDDDDDD|
+----+----------------+
```

|bytes|label|description|
|----:|----:|-----------|
|4|A|address >> 4|
|128|D|data|

---

### X format
##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|S|signature (0x58)|
|2|←↓|field delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

### Y format
##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|S|signature (0x59)|
|2|←↓|field delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

### 0 format
##### SIGNATURE
```
+---+
|S←↓|
+---+
```

|bytes|label|description|
|----:|----:|-----------|
|1|S|signature (0x30)|
|2|←↓|field delimiter (0x0d0a)|

##### HEADERS
TBD

##### FIRMWARE
TBD

---

credit goes to george hotz for reverse engineering the firmware encoding
