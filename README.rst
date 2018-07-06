### Cloud Insight Vul Score Sample

This is a simple example on how to utilize variety of Cloud Insight API in order to calculate cumulative vulnerability score

## Usage
Sample run:
```
python ci_vul_score_card.py --user $EMAIL_ADDRESS --pswd $PASSWORD --dc defender-us-denver --cid $CID
```

## Arguments
| Argument | Description |
| ------------- |-------------|
| --user | User name / email address for Insight API Authentication |
| --pswd | Password for Insight API Authentication |
| --dc | Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport |
| --cid | Target Alert Logic Customer ID for processing |
