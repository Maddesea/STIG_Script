from tests.test_utils import sample_xccdf_content

with open("dummy_xccdf.xml", "w", encoding="utf-8") as f:
    f.write(sample_xccdf_content())
