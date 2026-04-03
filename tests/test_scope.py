from password_strength.scope import V1_SCOPE


def test_v1_scope_version() -> None:
    assert V1_SCOPE.version == "1.0"


def test_known_in_scope_feature() -> None:
    assert V1_SCOPE.is_in_scope("strength scoring") is True


def test_known_out_of_scope_feature() -> None:
    assert V1_SCOPE.is_out_of_scope("password generator mode") is True


def test_unknown_feature_is_not_automatically_in_scope() -> None:
    assert V1_SCOPE.is_in_scope("live cloud sync") is False
