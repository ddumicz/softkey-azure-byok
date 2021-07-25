# SoftKEY Azure BYOK Tools

Example:
python3 softkey-azure-byok.py   --kid <key identifier of the KEK> \
                                --key-size 2048 \
                                --kek-in <KEKforBYOK.publickey.pem> \
                                --out <KeyTransferPackage-ContosoFirstHSMkey.byok>
                                