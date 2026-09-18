# Suricata SLM Training

Suricata SLM Training contains the resources and scripts for training SLM model using Suricata training rules.

The problem of whether a given Suricata rule is valid is easy to solve using Suricata CLI or AWS create Rule Group service. But the problem to fix or upgrade an existing Suricata rule into new Suricata version rule can be difficult. Suricata 8.0.3 transitions from PCRE1 to PCRE2 and the formalizes HTTP/2 and LDAP keywords.

## Training Approaches

  - A) **Prompt-Only Approach** (In-Context Learning)
    This approach does not require training time or low GPU cost. It works without training but relies on a massive, high-quality prompt that acts as a `mini-manual` for the model. Use prompting with Qwen2.5-Coder-7B-Instruct or 32B-Instruct (via an API or beefy local GPU). The "Coder" variant is significantly better at the regex and bracket logic required for Suricata. Set the temperature setting to 0.1 or 0 as we want the model to be deterministic and precise, not creative.

    ```
      <|im_start|>system
      You are a Suricata 8.0.3 Security Engineer specializing in signature repair.
      Your goal is to convert any incorrect, outdated, or broken Suricata rule into a valid, high-performance Suricata 8.0.3 rule.

      ### MANDATORY COMPLIANCE RULES (SURICATA 8.0.3):
      1. PCRE2 ENFORCEMENT: All 'pcre' keywords must follow PCRE2 standards. 
        - Escape curly braces used for quantifiers: use \{min,max\} instead of {min,max}.
        - PCRE1 specific shortcuts that are invalid in PCRE2 must be corrected.
      2. STICKY BUFFER PREFERENCE: Prioritize modern sticky buffers over older modifiers.
        - Use 'http.uri;' instead of 'content:"..."; http_uri;'.
        - Use 'http.header;' instead of the deprecated 'http2.header;' or 'http_header;'.
      3. NEW PROTOCOLS: Use specific protocol parsers for LDAP, HTTP2, Websocket, and SIP.
        - Example: For LDAP traffic, start the header with 'ldap' instead of 'tcp'.
      4. SYNTAX SANITIZATION: 
        - Ensure every option ends with a semicolon ';'.
        - Every rule must have a unique 'sid' (use 1000001+ if missing) and a 'rev'.
        - Ensure the 'msg' is descriptive and enclosed in double quotes.
      5. FLOW DIRECTION: Use established,to_server or to_client for stateful inspection.

      ### EXAMPLES:
      - Incorrect: alert tcp any any -> any 80 (msg:Missing Semicolon; content:"GET")
      - Fixed: alert http any any -> any any (msg:"Fixed Syntax"; http.method; content:"GET"; sid:1000001; rev:1;)

      - Incorrect: alert http any any -> any any (msg:"Old Buffer"; content:"/admin"; http_uri; pcre:"/[a-z]{3,5}/"; sid:2;)
      - Fixed: alert http any any -> any any (msg:"Modernized 8.0.3"; http.uri; content:"/admin"; pcre:"/[a-z]\{3,5\}/"; sid:2; rev:1;)

      ### TASK:
      Analyze the user's input. Fix all syntax, semantic, and version-specific errors. 
      Output ONLY the valid rule text.<|im_end|>
      <|im_start|>user
      [INSERT YOUR BROKEN RULE HERE]<|im_end|>
      <|im_start|>assistant
    ```

  - B) **LoRA Fine-Tuning Approach** (Fine-Tuning on T4 GPU)
    This approach combines Synthetic Data Generation combined with LoRA Fine-tuning. Model cannot rely on prompt details or few documentation pages to fix the rule. The model needs to see how rules break and how to fix them.
    This approach fine-tunes Lora model (Qwen 2.5 Coder 7B) using Unsloth. The model learns the underlying grammar patterns and can handle any incorrect rule.

  - C) **RAG Approach**
    Convert Suricata documentation to embeddings and store it in [FAISS](https://github.com/facebookresearch/faiss) or any vector database such as Pinecone, [Qdrant](https://github.com/qdrant/qdrant), [Milvus](https://github.com/milvus-io/milvus), [Chroma](https://github.com/chroma-core/chroma). Vector databases and FAISS are used for similarity search and clustering on vectors. Vector databases often use FAISS (or similar libraries) internally.
    Retrieve relevant syntax docs and inject into prompt to fix the rule using the Structured Prompting approach.

    RAG is good for answering questions, syntax lookup, explaining semantics, document reference, not for Deterministic rule rewriting.

  - D) **Teacher-Distilled SFT Approach**
    Convert the Suricata documentation into a dataset of "Bad Rule" vs. "Good Rule (8.0.3)" pairs with below json training set format. Generate 2000+ (5K-10K for excellence) examples of bad rules and their corrected Suricata 8.0.3 equivalents as  training data for the T4 SLM. Use teacher model like GPT-4o or Llama 3 70B for training.
    ```
      Below is a broken or outdated Suricata rule. 
      Correct it to follow Suricata 8.0.3 standards, including PCRE2 and new sticky buffers.

      ### Instruction:
      {}

      ### Input (Bad Rule):
      {}

      ### Response (Corrected 8.0.3 Rule):
      {}
    ```

### Desired Architecture

```
User Rule
   ↓
Validate with Suricata Binary CLI → capture error message
   ↓
Retrieve relevant documentation
   ↓
Fine-tuned 3B LoRA model
   ↓
Fixed rule
   ↓
Validate with Suricata Binary CLI
   ↓
If invalid → retry with error message
```

## Model Training

CodeBERT SLM is fine tuned to validate whether Suricata rule is good or bad rule.
Qwen SLM is fine tuned to fix the invalid/bad Suricata rule into valid/good Suricata rule. The Model should NOT change the original Suricata rule logic.

Model should avoid learning the training data too precisely, including noise and quirks, instead of just the general trends. 

Refer [Model Training Data Preparation](./training-data/README.md).

## GPU

### The Fine-Tuning Memory Formula

To calculate the exact VRAM requirement, we use the sum these four components:

$$VRAM_{total} = M_{weights} + M_{gradients} + M_{optimizer} + M_{activations}$$

1. **Model Weights** ($M_{weights}$): Memory needed to simply hold the model.
    - **16-bit (FP16/BF16):** $2 \times \text{Parameters}$
    - **32-bit (FP32):** $4 \times \text{Parameters}$

2. **Gradients** ($M_{gradients}$): GPU stores a gradient for every trainable parameter (weight) in the model during the backward pass. Full Fine-tuning usually matches weight precision (e.g. 2 bytes per parameter for 16-bit), while LoRA only stores for the tiny fraction of adapter layer parameters (often <1% of the model).

$$M_{gradients} = \text{Number of Trainable Parameters} \times \text{Bytes per Parameter}$$

3. **Optimizer States** ($M_{optimizer}$): Popular Optimizers like **AdamW** keep track of momentum and variance for every trainable parameter.
    - **Standard AdamW (FP32):** Adds **8 bytes** per parameter.
    - **8-bit Adam (bitsandbytes):** Adds only **2 bytes** per parameter.

4. **Activations** ($M_{activations}$): Intermediate values stored during the forward pass to be used in the backward pass. Activations scales **linearly** with **Batch Size** but **quadratically** with **Token Length** because of the self-attention mechanism. **Gradient Checkpointing** drastically reduces this by recomputing activations on the fly, though it makes training ~30% slower.


### Comparison Table (Estimated for a 7B Model)

| Method | Precision | Memory (7B Model) | Typical Hardware |
| --- | --- | --- | --- |
| **Full Fine-Tuning** | 16-bit | ~67 GB - 80 GB | A100 (80GB) or H100 |
| **LoRA** | 16-bit | ~16 GB - 20 GB | RTX 3090 / 4090 (24GB) |
| **QLoRA** | 4-bit | ~7 GB - 9 GB | RTX 3060 / 4070 (12GB) |


## GPU Configuration & Precision Matrix (72K datset using Unsloth 4-bit quantization)

| Nvidia GPU | BF16 Support | FP16 Support | Optimal Micro-Batch | Grad. Accumulation | Est. Training Time |
| --- | --- | --- | --- | --- | --- |
| **T4** | NO | **YES** | 4 | 4 | ~8 - 9 Hours |
| **L40S** | **YES** | YES | 16 | 1 | ~1.5 Hours |
| **H200** | **YES** | YES | 64 | 1 | ~30 Minutes |
| **A100 (40GB)** | **YES** | YES | 16 | 1 | ~1.2 Hours |
| **H100** | **YES** | YES | 32 | 1 | ~40 Minutes |


- [Model Memory Calculator](https://huggingface.co/spaces/hf-accelerate/model-memory-usage)
- [Can It Run LLM](https://huggingface.co/spaces/Vokturz/can-it-run-llm)


### Model Specs

Purpose: Check if Suricata Rule is Valid:

Suricata rules are essentially a Domain Specific Language (DSL). Suricata Header is (NL-like structure) and Options is (logic-like structure).

- CodeBERT
  - Encoder-only model
  - Trained on both Natural Language (NL) and Programming Languages
  - VRAM (4-6 GB) enough to run on a single T4 GPU

- UnixCoder 
  - Multi-modal Pre-training Model
  - Best for understanding the structure of code rather than just the keywords
  - VRAM (4-6 GB)

- DistilRoBERTa 
  - Lightweight model (2 GB VRAM)
  - Faster Training

Purpose: Fix Suricata Rule:

- 350M – 1.3B parameters
- Code-specialized models
- Good candidates: CodeT5-small, TinyLlama, Phi-2 style small transformers, Mistral-small
- Top Candidates: 
  - Microsoft’s Phi-3.5-mini-instruct (3.8B)
  - Qwen2.5-3B-Instruct (3B)
  - Qwen2.5-Coder-7B-Instruct (7B)
  - **Qwen/Qwen2.5-Coder-3B-Instruct (3B)**
  - Mistral-7B-Instruct (7B)
  - Phi-3-mini (3.8B)
  - Meta-Llama-3-8B (3.8B)
- Characteristics:
  - Token-level accuracy
  - Strong syntax modeling
  - Low hallucination tendency
  - Model should minimally modify rule.

 - Qwen (Specifically 2.5 Coder 3B): It is explicitly trained on code and structural syntax. It punches massively above its weight class (beating many 7B and 8B models on syntax tasks). At 3 Billion parameters, it trains lightning-fast on a T4 GPU without running out of memory, even with a 50K dataset.
 - Llama (Llama-3.2-3B): A very close second. Excellent reasoning, but Qwen slightly edges it out on raw code/syntax rigidity.
 - Phi (Phi-3.5-mini): Great, but its context structure and tokenizer are sometimes less flexible than Qwen's for deep technical formatting.
 - Mistral (Mistral-v0.3-7B): At 7B parameters, fine-tuning on 50,000 rows on a Free Colab T4 will be very slow and puts you at a high risk of Out-Of-Memory (OOM) errors and Colab timeouts.

### Training Data Requirements

- 10k – 50k rule pairs
- 3–5 epochs
- Batch size: 32–128
- Learning Rate: **2e-4**, 2e-5 to 5e-5
- Tokenizer: Default Phi-3 (BPE)
- Max Sequence Length: 512
- LoRA Rank (r): 16 or 32 (Lower r is faster; higher r captures more complexity.)
- LoRA Alpha: 32 (Usually 2 x r)

### Tokenization

Suricata rules are a domain-specific language (DSL), generic tokenization performs poorly.
Suricata DSL contains:
 - Operators: ->
 - Keywords: flow, content, http_header
 - Buffers: dns.query, tls.sni
 - Hashes: 4d5efa96609dc906f796e63cff009c2a
 - Structured delimiters: ; : ( )

Bad tokenization:
 - Increases sequence length
 - Reduces context efficiency
 - Breaks grammar modeling
 - Lowers syntax repair accuracy

Good tokenization:
 - Shorter sequences
 - Cleaner grammar representation
 - Better repair performance
 - Lower hallucination

 SentencePiece is a tokenizer training library by Google.
 - Learns token boundaries from your corpus
 - Builds vocabulary based on statistical frequency
 - Preserves domain-specific patterns naturally

 ```bash
 spm_train \
  --input=suricata_corpus.txt \
  --model_prefix=suricata_sp \
  --vocab_size=8000 \
  --character_coverage=1.0 \
  --model_type=bpe
 ```

 Default Configuration:
 - vocab_size: 6k–12k
 - model_type: bpe
 - character_coverage: 1.0 (important for Chinese/Japanese msg fields)
 - 50k rules
 - 10k broken variants
 - 5k real Suricata error messages

### Model Evaluation Strategy

Verify:
 - Does NOT invent unrelated keywords
 - Does NOT change rule logic

Expected Results:
 - With 20k high-quality examples:
 - 85–95% syntax repair success
 - 70–85% semantic repair success

## Training Library

Unsloth is the most memory-efficient library for fine-tuning e.g. Llama 3, allowing to fit the 8B model into the T4's limited memory with room to spare for a decent batch size.

| Feature | Standard Script | Unsloth Framework |
| --- | --- | --- |
| **Training Speed** | Baseline () | ** to  faster** |
| **VRAM Usage** | High (~12-14 GB) | **Low (~7-9 GB)** |
| **Max Context** | Hard to push past 512 | **Can easily do 1024 or 2048** |
| **Accuracy** | Baseline | **Identical** (Same math, faster kernels) |
| **Stability** | Prone to "Out of Memory" | **Very stable** (Reduced fragmentation) |

---

## Suricata Grammar & Semantic Repair Model (SGSRM)

Sequence-to-sequence code repair
Use Synthetic Data Generation combined with LoRA Fine-tuning.

### Key Tips for the Free Tier:

* **Dataset Size:** For simple syntax fixes, you only need 500–1,000 high-quality pairs. If you have 10,000+ rules, the T4 might take several hours.
* **Runtime:** Colab Free Tier often disconnects after 60–90 minutes of inactivity. Ensure you move the mouse or interact with the notebook occasionally.
* **Disk Space:** If you save checkpoints every epoch, you might run out of disk space. I set `save_strategy="no"` above; you can save the final model using `trainer.save_model("./final_fixer")`.


