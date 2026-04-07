import sys


def test_xml():
    from stig_assessor.core.deps import Deps

    ET, _ = Deps.get_xml()
    print("ET module is:", ET)
    print("Does it have Element?", hasattr(ET, "Element"))
    print(
        "sys.modules['xml.etree.ElementTree'] is:",
        sys.modules.get("xml.etree.ElementTree"),
    )
