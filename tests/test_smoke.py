import presidio_ai


def test_version_exposed():
    assert presidio_ai.__version__ == "0.7.0"
