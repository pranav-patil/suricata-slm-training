# CodeBERT Model Evaluation

Validated Good Suricata rules are randomized using `rule_randomizer.py`.

## V1: Original Good and Bad Rules - LORA-16

### GLOBAL EVALUATION RESULTS

**Overall Accuracy: 85.51%**

**Classification Report:**

|             |  precision   | recall | f1-score  | support |
|-------------|--------------|--------|-----------|---------|
|     INVALID |      0.80    |  1.00  |   0.89    | 19981   |
|       VALID |      1.00    |  0.66  |   0.80    | 14924   |
|    accuracy |              |        |   0.86    | 34905   |
|   macro avg |      0.90    |  0.83  |   0.84    | 34905   |
|weighted avg |      0.88    |  0.86  |   0.85    | 34905   |

### CATEGORY-SPECIFIC STATISTICS

| Category                  | Accuracy   | Count     |
|--------------------------|------------|-----------|
| Valid Dataset             |    99.98% | 5000      |
| Online Valid              |     0.00% | 4924      |
| Generated Valid           |    98.04% | 5000      |
| Invalid Dataset           |    99.98% | 5000      |
| AWS Invalid               |   100.00% | 4994      |
| Corrupted Invalid         |    99.36% | 4987      |
| Random Invalid            |   100.00% | 5000      |

---

## V2: Partially Mutated Good Rules, Random with Original Bad Rules - LORA-32

Randomize Good Suricata rules found online by varying the action, source and destination IP or CIDR addresses, source and destination ports, and the traffic direction. The order of rule options and rule protocols are not mutated for diversity.
The Bad Suricata rules contains half of Suricata rules from online which failed Suricata CLI validation and half generated using random Suricata rule generator using Suricata BNF syntax.

**Overall Accuracy: 79.26%**

**Classification Report:**

|             |  precision   | recall | f1-score  | support |
|-------------|--------------|--------|-----------|---------|
|     INVALID |      0.73    |  1.00  |   0.85    | 19971   |
|       VALID |      0.99    |  0.52  |   0.68    | 14934   |
|    accuracy |              |        |   0.79    | 34905   |
|   macro avg |      0.86    |  0.76  |   0.76    | 34905   |
|weighted avg |      0.85    |  0.79  |   0.78    | 34905   |

### CATEGORY-SPECIFIC STATISTICS

| Category                  | Accuracy   | Count     |
|--------------------------|------------|-----------|
| Valid Dataset             |   100.00% | 5000      |
| Online Valid              |     0.00% | 4937      |
| Generated Valid           |    54.73% | 4997      |
| Invalid Dataset           |   100.00% | 5000      |
| AWS Invalid               |   100.00% | 4994      |
| Corrupted Invalid         |    99.16% | 4977      |
| Random Invalid            |   100.00% | 5000      |

---

## V3: Partially Mutated Good Rules, Random with Original Bad Rules - LORA-16

**Overall Accuracy: 85.76%**

**Classification Report:**

|             |  precision   | recall | f1-score  | support |
|-------------|--------------|--------|-----------|---------|
|     INVALID |      0.80    |  1.00  |   0.89    | 19990   |
|       VALID |      1.00    |  0.67  |   0.80    | 14936   |
|    accuracy |              |        |   0.86    | 34926   |
|   macro avg |      0.90    |  0.83  |   0.84    | 34926   |
|weighted avg |      0.89    |  0.86  |   0.85    | 34926   |

### CATEGORY-SPECIFIC STATISTICS

| Category                  | Accuracy   | Count     |
|--------------------------|------------|-----------|
| Valid Dataset             |   100.00% | 5000      |
| Online Valid              |     0.00% | 4938      |
| Generated Valid           |    99.94% | 4998      |
| Invalid Dataset           |    99.90% | 5000      |
| AWS Invalid               |   100.00% | 4994      |
| Corrupted Invalid         |    99.44% | 4996      |
| Random Invalid            |   100.00% | 5000      |

---

## V4: Mutated Good Rules, Random Bad Rules - LORA-16

### GLOBAL EVALUATION RESULTS

**Overall Accuracy: 57.04%**

**Classification Report:**

|             |  precision   | recall | f1-score  | support |
|-------------|--------------|--------|-----------|---------|
|     INVALID |      1.00    |  0.25  |   0.40    | 19987   |
|       VALID |      0.50    |  1.00  |   0.67    | 14911   |
|    accuracy |              |        |   0.57    | 34898   |
|   macro avg |      0.75    |  0.62  |   0.53    | 34898   |
|weighted avg |      0.78    |  0.57  |   0.51    | 34898   |

### CATEGORY-SPECIFIC STATISTICS

| Category                  | Accuracy   | Count     |
|--------------------------|------------|-----------|
| Valid Dataset             |    99.80% | 4994      |
| Online Valid              |    99.96% | 4923      |
| Generated Valid           |    99.98% | 4994      |
| ...                       | ...        | ...       |
| AWS Invalid               |     0.14% | 4994      |
| Corrupted Invalid         |     0.06% | 4993      |
| Random Invalid            |    99.98% | 5000      |

---

## V5: Mutated Good Rules, Mutated Bad Rules - LORA-16

The Good Suricata Rules are randomized along with protocol mutation and shuffling of rule options order.

### GLOBAL EVALUATION RESULTS

**Overall Accuracy: 52.87%**

**Classification Report:**

|            |  precision   | recall | f1-score  | support |
|------------|--------------|--------|-----------|---------|
|     INVALID|      0.68    |  0.34  |   0.45    | 19986   |
|       VALID|      0.47    |  0.78  |   0.59    | 14919   |
|    accuracy|              |        |  0.53     | 34905   |
|   macro avg|      0.57    | 0.56   |  0.52     | 34905   |
|weighted avg|      0.59    | 0.53   |  0.51     | 34905   |

### CATEGORY-SPECIFIC STATISTICS

| Category                  | Accuracy   | Count     |
|--------------------------|------------|-----------|
| Valid Dataset             |    62.74% | 4997      |
| Online Valid              |    71.85% | 4924      |
| Generated Valid           |    99.74% | 4998      |
| ...                       | ...        | ...       |
| AWS Invalid               |     0.42% | 4994      |
| Corrupted Invalid         |    21.39% | 4992      |
| Random Invalid            |   100.00% | 5000      |

---

## Fine Tuned CodeBERT Model Accuracy Comparison

| Category          |    V1     |    V2     |    V3     |    V4     |    V5     |
|-------------------|:---------:|:---------:|:---------:|:---------:|:---------:|
| Valid Dataset     |  100.00%  |  100.00%  |   99.98%  |   99.80%  |   62.74%  |
| Online Valid      |    0.00%  |    0.00%  |    0.00%  |   99.96%  |   71.85%  |
| Generated Valid   |   99.94%  |   54.73%  |   98.04%  |   99.98%  |   99.74%  |
| Invalid Dataset   |   99.90%  |  100.00%  |   99.98%  |   99.98%  |  100.00%  |
| AWS Invalid       |  100.00%  |  100.00%  |  100.00%  |    0.14%  |    0.42%  |
| Corrupted Invalid |   99.44%  |   99.16%  |   99.36%  |    0.06%  |   21.39%  |
| Random Invalid    |  100.00%  |  100.00%  |  100.00%  |   99.98%  |  100.00%  |
|                   |           |           |           |           |           |
| **Overall**       | **85.76%** | **79.26%** | **85.51%** | **57.04%** | **52.87%** |


