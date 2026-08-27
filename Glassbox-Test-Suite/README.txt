GLASSBOX DEMONSTRATION CORPUS
=============================

Purpose
-------
Open these files ONE AT A TIME in Glassbox using Open .txt / .bin.
Each sample is synthetic but named after a plausible real-world artefact so you know what kind of structure you are looking for.

Important
---------
Every sample has a .txt extension because the current Glassbox picker accepts .txt/.bin.
Some files contain raw binary bytes despite the .txt extension. That is deliberate.

Recommended demo order
----------------------
01 -> 02 -> 04 -> 05 -> 07 -> 03 -> 06 -> 08 -> 09 -> 10

01_SOC_Shift_Handover_Report.txt
--------------------------------
Real-life analogue: A normal SOC/helpdesk handover note or incident summary.
Expected: TEXT / PLAINTEXT. Glassbox should stay boring and avoid inventing crypto or record structure.
Inspect: Hypothesis/verdict, Strings, Byte Frequency, Hilbert/Digraph. This is the control sample.
Size: 686 bytes

02_Building_IoT_Sensor_Telemetry.txt
------------------------------------
Real-life analogue: A binary export from a building-management sensor gateway.
Expected: Strong fixed-width record structure, ideally a ~48-byte stride with visible recurring fields/columns and strings such as SENSOR01 and ROOM-A.
Inspect: Stride, Columns, Strings, Digraph/Hilbert, Byte Map. Click the stride/column evidence.
Size: 4,624 bytes

03_Branch_Firewall_Config_Backup.txt
------------------------------------
Real-life analogue: A configuration backup that has been compressed and Base64-wrapped for transport.
Expected: Encoded/transformed data. The decode chain should identify Base64, then gzip/DEFLATE, and expose readable JSON underneath if the integrated decode ladder is active.
Inspect: Decode Chain, Hypotheses, Strings after decode, provenance/ancestry. This demonstrates 'wrapped data' reasoning.
Size: 333 bytes

04_Payment_Terminal_Encrypted_Batch_ECB_Like.txt
------------------------------------------------
Real-life analogue: A badly designed legacy payment-terminal batch encrypted in a block mode that leaks repeated plaintext structure.
Expected: REPEATED BLOCK STRUCTURE / ECB-like behaviour. Repeated aligned 16-byte ciphertext blocks should stand out strongly.
Inspect: Repeated Blocks, Byte Map, Hypothesis evidence, entropy. Compare directly with sample 05.
Size: 12,288 bytes

05_VPN_Session_Encrypted_Capture_No_Repeats.txt
-----------------------------------------------
Real-life analogue: A ciphertext-like VPN/session payload where equal plaintext blocks do not produce repeated ciphertext blocks.
Expected: HIGH ENTROPY with little/no repeated block structure. It should be much quieter than sample 04.
Inspect: Entropy, Repetition, Byte Frequency, Hilbert/Digraph. This is the negative control for ECB detection.
Size: 12,288 bytes

06_Industrial_Controller_Firmware_Update.txt
--------------------------------------------
Real-life analogue: A firmware/update image containing headers, embedded resources, a cryptographic lookup table, compressed configuration, and opaque payload data.
Expected: Mixed structure. Expect signatures/segments/strings plus a candidate 256-byte permutation (AES S-box) around offset 0x900, which should be drillable into the crypto cluster.
Inspect: Hypotheses, Signatures, Segments, Strings, Entropy, Byte Map. Open the candidate S-box and inspect DDT/LAT/Walsh.
Size: 4,797 bytes

07_Server_Backup_Image_With_Compressed_Payload.txt
--------------------------------------------------
Real-life analogue: A backup/container image with a readable header/index, padding, a compressed-or-encrypted payload region, then a trailer.
Expected: Clear entropy/segmentation transitions: readable low/moderate-entropy regions, zero padding, then a high-entropy payload.
Inspect: Entropy Timeline, Segments, Strings, Hilbert/Byte Map. Click across the boundaries.
Size: 15,579 bytes

08_Legacy_Router_XOR_Obfuscated_Diagnostics.txt
-----------------------------------------------
Real-life analogue: A legacy embedded-device diagnostic/configuration dump hidden with repeating-key XOR.
Expected: If the XOR detector is active in this build, it should propose a short repeating-key XOR and recover or point toward key CANBERRA / readable plaintext.
Inspect: Hypotheses, periodicity/stride evidence, decode/transform ancestry if offered. This is a more advanced engine test.
Size: 6,426 bytes

09_Office_Access_Control_Badge_Log.txt
--------------------------------------
Real-life analogue: A binary physical-access-control log from office badge readers.
Expected: Fixed 32-byte records, repeating door names, counters/timestamps/enums, and column structure.
Inspect: Stride, Columns, Strings, Hypothesis evidence. Compare its inferred layout with sample 02.
Size: 4,112 bytes

10_Incident_Response_Evidence_Bundle.txt
----------------------------------------
Real-life analogue: A made-up incident-response collection containing metadata, fixed binary records, an encoded/compressed artefact, padding, and an opaque tail.
Expected: Multiple structures in one file. Expect several hypotheses rather than one neat classification, with useful segmentation and cross-highlighting.
Inspect: Hypothesis board first, then Segments, Stride/Columns, Strings, Entropy, Decode Chain. This is the 'show the whole product' sample.
Size: 6,652 bytes
