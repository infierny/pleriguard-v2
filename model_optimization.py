import re

# Read classifier file
with open('classification/classifier.py', 'r') as f:
    content = f.read()

# Replace model reference - find the model definition
if 'MiniMax-M2.7' in content:
    content = content.replace('MiniMax-M2.7', 'qwen3:8b')
    print("✅ Updated model: MiniMax-M2.7 -> qwen3:8b")

# Also replace any direct minimax references
content = re.sub(r'minimax/MiniMax-M2\.7', 'qwen3:8b', content)
content = re.sub(r'"minimax/MiniMax-M2\.7"', '"qwen3:8b"', content)

# Update batch size for faster processing 
content = re.sub(r'LIMIT 10', 'LIMIT 20', content)

# Write optimized classifier
with open('classification/classifier_optimized.py', 'w') as f:
    f.write(content)

print("✅ Classifier optimized")
print("  - Model: qwen3:8b (~3x cheaper)")
print("  - Batch size: 10->20 domains")
