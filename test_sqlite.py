import os
from stig_assessor.history.sqlite_store import SQLiteStore

def run_test():
    test_db = "test_history.db"
    if os.path.exists(test_db):
        os.remove(test_db)
        
    db = SQLiteStore(test_db)
    
    res1 = [
        {"vid": "V-111", "status": "NotAFinding", "severity": "high", "find": "ok", "comm": ""},
        {"vid": "V-222", "status": "Open", "severity": "medium", "find": "bad", "comm": ""},
        {"vid": "V-333", "status": "Not_Reviewed", "severity": "low", "find": "", "comm": ""},
    ]
    id1 = db.save_assessment("SERVER_A", "file1.ckl", "Win11", res1)
    
    res2 = [
        {"vid": "V-111", "status": "NotAFinding", "severity": "high", "find": "ok", "comm": ""},
        {"vid": "V-222", "status": "NotAFinding", "severity": "medium", "find": "fixed", "comm": ""},
        {"vid": "V-333", "status": "Open", "severity": "low", "find": "failed", "comm": ""},
        {"vid": "V-444", "status": "Not_Reviewed", "severity": "low", "find": "", "comm": ""}, # new rule
    ]
    id2 = db.save_assessment("SERVER_A", "file2.ckl", "Win11", res2)
    
    # Save a justification
    db.save_justification("V-222", "Open", "Business required exception", "admin")
    
    drift = db.get_drift("SERVER_A", id2)
    
    assert len(drift["fixed"]) == 1
    assert drift["fixed"][0]["vid"] == "V-222"
    
    assert len(drift["changed"]) == 1
    assert drift["changed"][0]["vid"] == "V-333"
    assert drift["changed"][0]["to"] == "Open"
    
    assert len(drift["unchanged"]) == 1
    assert drift["unchanged"][0]["vid"] == "V-111"

    assert len(drift["new"]) == 1
    assert drift["new"][0]["vid"] == "V-444"
    
    just = db.get_justification("V-222")
    assert just["status"] == "Open"
    assert "Business required" in just["comments"]

    print("Success: SQLite Engine verified.")
    
if __name__ == "__main__":
    run_test()
