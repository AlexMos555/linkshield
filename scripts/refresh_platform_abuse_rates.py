#!/usr/bin/env python3
"""Recompute data/platform_abuse_rates.json from the training feeds.

Run scripts/refresh_training_feeds.py first. The file is part of the model
(the model was trained on its values), so retrain right after, or use
`python ml/train_model.py --refresh-platform-rates`, which does both.
See ml/platform_abuse_rates.py.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ml"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from platform_abuse_rates import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
