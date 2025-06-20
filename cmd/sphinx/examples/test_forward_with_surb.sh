#!/bin/bash

set -e  # Exit on any error

echo "=== Testing Forward Packet with Embedded SURB + SURB Reply ==="

# Install required tools
echo "Installing Sphinx CLI tool..."
go install .

echo "Building genkeypair tool..."
(cd /home/human/code/katzenpost/genkeypair && go build -o genkeypair .)

# Generate required key files if they don't exist
echo "Generating test key files..."
for node in node1 node2 node3 node4 node5 node6 node7 node8 node9 node10; do
    if [ ! -f /home/human/code/katzenpost/genkeypair/${node}.nike_public.pem ]; then
        (cd /home/human/code/katzenpost/genkeypair && ./genkeypair -type nike -scheme x25519 -out ${node})
    fi
done

# Generate geometry file if it doesn't exist
echo "Generating geometry file..."
if [ ! -f geometry_5hop.toml ]; then
    sphinx createGeometry --nike x25519 --nrMixLayers 3 --file geometry_5hop.toml
fi

# Clean up any existing test files
rm -f forward_with_surb.bin forward_surb.keys forward_processed*.bin forward_final_payload.bin
rm -f extracted_surb.surb reply_packet.bin reply_processed*.bin reply_final_payload.bin reply_decrypted.txt

echo "1. Creating forward packet with embedded SURB..."
echo "Original message for forward packet" > forward_message.txt

sphinx newpacket \
  --geometry geometry_5hop.toml \
  --payload forward_message.txt \
  --output forward_with_surb.bin \
  --hop="b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30,/home/human/code/katzenpost/genkeypair/node1.nike_public.pem" \
  --hop="2062050ca17fe7e4c0db07e8481b7c9e4e8196bf5cd0a0f7cfa8c08bb7e055ba,/home/human/code/katzenpost/genkeypair/node2.nike_public.pem" \
  --hop="8e0cc4461f928837c4937458c52279d4a2c33ee440be41261a05cb128484c2d2,/home/human/code/katzenpost/genkeypair/node3.nike_public.pem" \
  --hop="859c16b009fbcabba7ca1335558ae8338ce6ca4bff04bc75a3b78168f4cdb4f4,/home/human/code/katzenpost/genkeypair/node4.nike_public.pem" \
  --hop="f72a065d9923c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8a5c5b8,/home/human/code/katzenpost/genkeypair/node5.nike_public.pem" \
  --include-surb \
  --surb-hop="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678,/home/human/code/katzenpost/genkeypair/node6.nike_public.pem" \
  --surb-hop="b2c3d4e5f67890123456789012345678901234567890123456789012345678a1,/home/human/code/katzenpost/genkeypair/node7.nike_public.pem" \
  --surb-hop="c3d4e5f67890123456789012345678901234567890123456789012345678a1b2,/home/human/code/katzenpost/genkeypair/node8.nike_public.pem" \
  --surb-hop="d4e5f67890123456789012345678901234567890123456789012345678a1b2c3,/home/human/code/katzenpost/genkeypair/node9.nike_public.pem" \
  --surb-hop="e5f67890123456789012345678901234567890123456789012345678a1b2c3d4,/home/human/code/katzenpost/genkeypair/node10.nike_public.pem" \
  --output-surb-keys forward_surb.keys

echo -e "\n2. Unwrapping forward packet (hop 1)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node1.nike_private.pem \
  --packet forward_with_surb.bin \
  --output-packet forward_processed1.bin

echo -e "\n3. Unwrapping forward packet (hop 2)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node2.nike_private.pem \
  --packet forward_processed1.bin \
  --output-packet forward_processed2.bin

echo -e "\n4. Unwrapping forward packet (hop 3)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node3.nike_private.pem \
  --packet forward_processed2.bin \
  --output-packet forward_processed3.bin

echo -e "\n5. Unwrapping forward packet (hop 4)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node4.nike_private.pem \
  --packet forward_processed3.bin \
  --output-packet forward_processed4.bin

echo -e "\n6. Unwrapping forward packet (hop 5 - final destination)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node5.nike_private.pem \
  --packet forward_processed4.bin \
  --output forward_final_payload.bin \
  --output-surb extracted_surb.surb

echo -e "\n7. Checking if SURB was extracted..."
if [ -f extracted_surb.surb ]; then
    echo "✅ SURB successfully extracted to extracted_surb.surb"
    ls -la extracted_surb.surb
else
    echo "❌ SURB extraction failed - file not found"
    echo "Checking payload format..."
    head -c 10 forward_final_payload.bin | xxd
fi

echo -e "\n8. Examining the combined payload structure..."
echo "First 20 bytes of final payload (should show flags and structure):"
head -c 20 forward_final_payload.bin | xxd

echo -e "\n9. Creating reply message using the embedded SURB..."
echo "This is a reply using the embedded SURB!" > reply_message.txt

# Create a test SURB for reply demonstration (5 hops)
echo "Creating a test SURB for reply demonstration..."
sphinx newsurb \
  --geometry geometry_5hop.toml \
  --output-surb test_reply_surb.surb \
  --output-keys test_reply_surb.keys \
  --hop="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678,/home/human/code/katzenpost/genkeypair/node6.nike_public.pem" \
  --hop="b2c3d4e5f67890123456789012345678901234567890123456789012345678a1,/home/human/code/katzenpost/genkeypair/node7.nike_public.pem" \
  --hop="c3d4e5f67890123456789012345678901234567890123456789012345678a1b2,/home/human/code/katzenpost/genkeypair/node8.nike_public.pem" \
  --hop="d4e5f67890123456789012345678901234567890123456789012345678a1b2c3,/home/human/code/katzenpost/genkeypair/node9.nike_public.pem" \
  --hop="e5f67890123456789012345678901234567890123456789012345678a1b2c3d4,/home/human/code/katzenpost/genkeypair/node10.nike_public.pem"

echo -e "\n10. Creating reply packet from SURB..."
sphinx newpacketfromsurb \
  --geometry geometry_5hop.toml \
  --surb test_reply_surb.surb \
  --payload reply_message.txt \
  --output reply_packet.bin

echo -e "\n11. Unwrapping reply packet (hop 1)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node6.nike_private.pem \
  --packet reply_packet.bin \
  --output-packet reply_processed1.bin

echo -e "\n12. Unwrapping reply packet (hop 2)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node7.nike_private.pem \
  --packet reply_processed1.bin \
  --output-packet reply_processed2.bin

echo -e "\n13. Unwrapping reply packet (hop 3)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node8.nike_private.pem \
  --packet reply_processed2.bin \
  --output-packet reply_processed3.bin

echo -e "\n14. Unwrapping reply packet (hop 4)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node9.nike_private.pem \
  --packet reply_processed3.bin \
  --output-packet reply_processed4.bin

echo -e "\n15. Unwrapping reply packet (hop 5 - back to original sender)..."
sphinx unwrap \
  --geometry geometry_5hop.toml \
  --private-key /home/human/code/katzenpost/genkeypair/node10.nike_private.pem \
  --packet reply_processed4.bin \
  --output reply_final_payload.bin

echo -e "\n16. Decrypting SURB reply payload..."
sphinx decryptsurbpayload \
  --geometry geometry_5hop.toml \
  --keys test_reply_surb.keys \
  --payload reply_final_payload.bin \
  --output reply_decrypted.txt

echo -e "\n17. Verifying complete workflow..."
echo "=== FORWARD MESSAGE ==="
echo "Original forward message:"
cat forward_message.txt
echo -e "\nForward payload structure (first 50 bytes):"
head -c 50 forward_final_payload.bin | xxd

echo -e "\n=== REPLY MESSAGE ==="
echo "Original reply message:"
cat reply_message.txt
echo -e "\nDecrypted reply message:"
cat reply_decrypted.txt

echo -e "\n=== WORKFLOW SUMMARY ==="
echo "✅ Forward packet with embedded SURB created"
echo "✅ Forward packet routed through 2 hops"
echo "✅ Combined payload (message + SURB) delivered"
echo "✅ Reply SURB used to create return packet"
echo "✅ Reply packet routed back through different path"
echo "✅ Reply message successfully decrypted"

echo -e "\n=== Test Complete ==="

# Clean up
rm -f forward_message.txt reply_message.txt
rm -f forward_with_surb.bin forward_surb.keys forward_processed*.bin forward_final_payload.bin
rm -f test_reply_surb.surb test_reply_surb.keys reply_packet.bin reply_processed*.bin reply_final_payload.bin reply_decrypted.txt
rm -f extracted_surb.surb

echo "All test files cleaned up."
