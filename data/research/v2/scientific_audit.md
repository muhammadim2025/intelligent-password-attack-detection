# Version 2 Scientific Audit

Overall: **PASS**

| Check | Result |
|---|---|
| direct_target_feature_exclusion | PASS |
| scenario_ground_truth_consistency | PASS |
| chronological_primary_split | PASS |
| unseen_source_holdout_exists | PASS |
| train_test_source_overlap_documented | PASS |
| source_history_at_prediction_time | PASS |
| account_history_at_prediction_time | PASS |
| unique_accounts_not_shortcut | PASS |
| no_random_label_inversion | PASS |
| baseline_training_only_threshold_selection | PASS |
| heldout_test_not_tuning | PASS |

## Remaining Limitations

- All accounts, sources, and sequences are synthetic.
- Scenario labels are assumptions, not observed attack ground truth.
- The generator does not model real authentication identity providers or network telemetry.
- External real-world validation and privacy impact review remain required.
- The V2 model must not be loaded into production authentication until independently approved.
