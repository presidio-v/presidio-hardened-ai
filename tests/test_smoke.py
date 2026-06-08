import presidio_ai


def test_version_exposed():
    assert presidio_ai.__version__ == "0.5.0"
