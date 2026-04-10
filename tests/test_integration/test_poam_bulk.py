import unittest
import tempfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from stig_assessor.processor.processor import Proc as STIGProcessor
from stig_assessor.core.constants import Status


class TestPOAMBulk(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.temp_ckl = self.tmp_dir / "test_poam_bulk.ckl"
        with open(self.temp_ckl, "w") as f:
            f.write("""<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>TEST-HOST</HOST_NAME>
    </ASSET>
    <STIGS>
        <iSTIG>
            <VULN>
                <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
                <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
                <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule 1 high</ATTRIBUTE_DATA></STIG_DATA>
                <STATUS>Open</STATUS>
                <FINDING_DETAILS>finding 1</FINDING_DETAILS>
                <COMMENTS>comment 1</COMMENTS>
            </VULN>
            <VULN>
                <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-2</ATTRIBUTE_DATA></STIG_DATA>
                <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
                <STATUS>NotAFinding</STATUS>
                <FINDING_DETAILS></FINDING_DETAILS>
                <COMMENTS></COMMENTS>
            </VULN>
            <VULN>
                <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-3</ATTRIBUTE_DATA></STIG_DATA>
                <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>low</ATTRIBUTE_DATA></STIG_DATA>
                <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule 3 low test</ATTRIBUTE_DATA></STIG_DATA>
                <STATUS>Not_Reviewed</STATUS>
                <FINDING_DETAILS></FINDING_DETAILS>
                <COMMENTS></COMMENTS>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>""")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_export_poam(self):
        processor = STIGProcessor()
        csv_str = processor.export_poam(self.temp_ckl)
        
        self.assertIn("Control Number,Vulnerability Description,Severity,Status,Comments,Checklist Name", csv_str)
        # Should only include Open and Not_Reviewed (V-1, V-3), Should NOT include NotAFinding (V-2)
        self.assertIn("V-1,Rule 1 high,HIGH,Open,comment 1,test_poam_bulk.ckl", csv_str)
        self.assertIn("V-3,Rule 3 low test,LOW,Not_Reviewed,,test_poam_bulk.ckl", csv_str)
        self.assertNotIn("V-2", csv_str)

    def test_bulk_edit_severity(self):
        processor = STIGProcessor()
        out_path = self.tmp_dir / "out1.ckl"
        
        res = processor.bulk_edit(
            self.temp_ckl, 
            out_path, 
            severity="low", 
            new_status=Status.NOT_A_FINDING, 
            new_comment="Mass changed due to risk acceptance"
        )
        
        self.assertTrue(res["ok"])
        self.assertEqual(res["updates"], 1)
        
        # Verify the output
        tree = ET.parse(out_path)
        root = tree.getroot()
        v3_status = None
        v3_comment = None
        for vuln in root.findall(".//VULN"):
            for sd in vuln.findall("STIG_DATA"):
                if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num" and sd.findtext("ATTRIBUTE_DATA") == "V-3":
                    v3_status = vuln.findtext("STATUS")
                    v3_comment = vuln.findtext("COMMENTS")
                    break
        
        self.assertEqual(v3_status, Status.NOT_A_FINDING)
        self.assertEqual(v3_comment, "Mass changed due to risk acceptance")

    def test_bulk_edit_regex(self):
        processor = STIGProcessor()
        out_path = self.tmp_dir / "out2.ckl"
        
        # Matches V-1 and V-2 but not V-3
        res = processor.bulk_edit(
            self.temp_ckl, 
            out_path, 
            regex_vid="V-[12]", 
            new_status=Status.NOT_APPLICABLE, 
            new_comment="Regex match",
            append_comment=True
        )
        
        self.assertTrue(res["ok"])
        self.assertEqual(res["updates"], 2)
        
        tree = ET.parse(out_path)
        root = tree.getroot()
        v1_status = ""
        v1_comment = ""
        
        for vuln in root.findall(".//VULN"):
            for sd in vuln.findall("STIG_DATA"):
                if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num" and sd.findtext("ATTRIBUTE_DATA") == "V-1":
                    v1_status = vuln.findtext("STATUS")
                    v1_comment = vuln.findtext("COMMENTS")
                    break
                    
        self.assertEqual(v1_status, Status.NOT_APPLICABLE)
        self.assertEqual(v1_comment, "comment 1\nRegex match")


if __name__ == "__main__":
    unittest.main()
