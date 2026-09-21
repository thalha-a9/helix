import re

import pytest

from osint.permutations import generate_permutations
from osint.email_permutations import generate_email_permutations

VALID = re.compile(r'^[a-zA-Z0-9._\-]+$')


def test_generates_variations():
    perms = generate_permutations("johndoe")
    assert "johndoe1" in perms
    assert "realjohndoe" in perms
    assert "johndoe_dev" in perms


def test_original_username_excluded():
    perms = generate_permutations("johndoe")
    assert "johndoe" not in perms


def test_camelcase_split_into_separators():
    perms = generate_permutations("JohnDoe")
    assert "john_doe" in perms
    assert "john.doe" in perms


def test_separator_swaps():
    perms = generate_permutations("john_doe")
    assert "john.doe" in perms
    assert "johndoe" in perms
    assert "john-doe" in perms


def test_trailing_digits_stripped_to_base():
    assert "john" in generate_permutations("john123")


def test_all_results_are_valid_usernames():
    for perm in generate_permutations("john.doe-99"):
        assert VALID.match(perm), perm
        assert 1 < len(perm) <= 50


def test_results_sorted_and_unique():
    perms = generate_permutations("johndoe")
    assert perms == sorted(perms)
    assert len(perms) == len(set(perms))


@pytest.mark.parametrize("username", ["a", "x1", "a-b"])
def test_short_usernames_do_not_crash(username):
    assert isinstance(generate_permutations(username), list)


def test_email_permutations_use_real_name_when_available():
    emails = generate_email_permutations("jroe", "Jane Roe")
    assert emails
    assert all("@" in e for e in emails)


def test_email_permutations_from_username_alone():
    assert generate_email_permutations("jroe", "")
