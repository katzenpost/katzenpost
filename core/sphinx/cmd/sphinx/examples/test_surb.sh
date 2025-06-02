#!/bin/bash

set -e  # Exit on any error

echo "=== Testing Complete SURB Functionality ==="

# Build required tools
echo "Building Sphinx CLI tool..."
go build -o sphinx .

echo "Building genkeypair tool..."
(cd /home/human/code/katzenpost/genkeypair && go build -o genkeypair .)

# Generate required key files if they don't exist
echo "Generating test key files..."
for node in node1 node2 node3 node4 node5; do
    if [ ! -f /home/human/code/katzenpost/genkeypair/${node}.nike_public.pem ]; then
        (cd /home/human/code/katzenpost/genkeypair && ./genkeypair -type nike -scheme x25519 -out ${node})
    fi
done

# Generate geometry file if it doesn't exist
echo "Generating geometry file..."
if [ ! -f geometry_5hop.toml ]; then
    ./sphinx createGeometry --nike x25519 --nrMixLayers 3 --file geometry_5hop.toml
fi

# Clean up any existing test files
rm -f test_surb.surb test_surb.keys test_reply.bin test_reply_processed*.bin test_final_payload.bin test_decrypted.txt

echo "1. Creating SURB..."
./sphinx newsurb \
  --geometry geometry_5hop.toml \
  --output-surb test_surb.surb \
  --output-keys test_surb.keys \
  --hop="b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30,/home/human/code/katzenpost/genkeypair/node1.nike_public.pem" \
  --hop="2062050ca17fe7e4c0db07e8481b7c9e4e8196bf5cd0a0f7cfa8c08bb7e055ba,/home/human/code/katzenpost/genkeypair/node2.nike_public.pem" \
  --hop="8e0cc4461f928837c4937458c52279d4a2c33ee440be41261a05cb128484c2d2,/home/human/code/katzenpost/genkeypair/node3.nike_public.pem" \
  --hop="859c16b009fbcabba7ca1335558ae8338ce6ca4bff04bc75a3b78168f4cdb4f4,/home/human/code/katzenpost/genkeypair/node4.nike_public.pem" \
  --hop="f72a065d9923c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8,/home/human/code/katzenpost/genkeypair/node5.nike_public.pem"

echo -e "\n2. Creating reply message..."
echo "Hello from SURB reply test!" > test_message.txt

echo -e "\n3. Creating packet from SURB..."
./sphinx newpacketfromsurb \
  --geometry geometry_5hop.toml \
  --surb test_surb.surb \
  --payload test_message.txt \
  --output test_reply.bin

echo -e "\n4. Unwrapping packet (hop 1)..."
./sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node1.nike_private.pem \
  --packet test_reply.bin \
  --output-packet test_reply_processed1.bin

echo -e "\n5. Unwrapping packet (hop 2)..."
./sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node2.nike_private.pem \
  --packet test_reply_processed1.bin \
  --output-packet test_reply_processed2.bin

echo -e "\n6. Unwrapping packet (hop 3)..."
./sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node3.nike_private.pem \
  --packet test_reply_processed2.bin \
  --output-packet test_reply_processed3.bin

echo -e "\n7. Unwrapping packet (hop 4)..."
./sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node4.nike_private.pem \
  --packet test_reply_processed3.bin \
  --output-packet test_reply_processed4.bin

echo -e "\n8. Unwrapping packet (hop 5 - final)..."
./sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node5.nike_private.pem \
  --packet test_reply_processed4.bin \
  --output test_final_payload.bin

echo -e "\n9. Decrypting SURB payload..."
./sphinx decryptsurbpayload \
  --geometry geometry_5hop.toml \
  --keys test_surb.keys \
  --payload test_final_payload.bin \
  --output test_decrypted.txt

echo -e "\n10. Verifying result..."
echo "Original message:"
cat test_message.txt
echo -e "\nDecrypted message:"
head -c 50 test_decrypted.txt

echo -e "\n\n=== SURB Test Complete ==="

# Clean up
rm -f test_message.txt test_surb.surb test_surb.keys test_reply.bin test_reply_processed*.bin test_final_payload.bin test_decrypted.txt

echo "All test files cleaned up."
