"""Gate: malicious relay URL through the real pairing commit path.

``_check_relay_url`` is only the inner check; these tests drive the real
inviter-side commit (``model.invites.commit_pairing``, the function the
``mas pair commit`` CLI calls) with a fully valid ceremony (invite,
acceptance, human-approved verification) and a hostile relay URL, and
prove the rejection carries the stable ``bad_relay_url`` code with no
relationship row and no invite state change.

Also documented: the check is prefix-only (``https://`` or ``git@``), so
a credential-embedded URL such as ``https://user:pass@github.com/o/r``
passes the model layer; the CLI's transport inference then refuses it
with ``bad_args`` because it is not a GitHub relay URL.
"""

import argparse
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
)
from muse_agent_social.model.cards import card_fingerprint, create_card
from muse_agent_social.model.invites import (
    PairingError,
    commit_pairing,
    create_acceptance,
    create_invite,
    record_verification,
)

UTC = timezone.utc


def _card(display, principal):
    ed_priv = Ed25519PrivateKey.generate()
    x_priv = X25519PrivateKey.generate()
    card = create_card(
        identity_priv=ed_priv,
        display_name=display,
        principal_label=principal,
        agreement_pub_multibase=agreement_key_multibase_from_pubkey(
            x_priv.public_key().public_bytes_raw()
        ),
        capabilities=["chat"],
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    return ed_priv, card


def _deploy_pubkey() -> str:
    priv = Ed25519PrivateKey.generate()
    return (
        priv.public_key()
        .public_bytes(serialization.Encoding.OpenSSH,
                      serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )


@pytest.fixture()
def ceremony(tmp_path):
    """A complete, valid pairing ceremony up to the commit step."""
    from support.harness import fresh_db

    conn = fresh_db(tmp_path / "pairing.db")
    inviter_priv, inviter_card = _card("Alice", "PrincipalA")
    acceptor_priv, acceptor_card = _card("Bob", "PrincipalB")
    invite = create_invite(
        conn=conn,
        inviter_card=inviter_card,
        inviter_priv=inviter_priv,
        ephemeral_priv=X25519PrivateKey.generate(),
        requested_capabilities=["chat"],
        requested_policy={},
    )
    rel_priv = X25519PrivateKey.generate()
    acceptance = create_acceptance(
        conn,
        invite,
        acceptor_card,
        acceptor_priv,
        agreement_key_multibase_from_pubkey(
            rel_priv.public_key().public_bytes_raw()
        ),
        _deploy_pubkey(),
    )
    # Inviter-side arrival of the acceptance: consume the invite's one-use
    # status, then the human-approved eight-word comparison, exactly as the
    # CLI's pair commit flow does.
    from muse_agent_social.model.invites import validate_invite

    validate_invite(conn, invite)
    record_verification(
        conn,
        invite["invite_id"],
        (card_fingerprint(inviter_card), card_fingerprint(acceptor_card)),
        human_approved=True,
    )
    return {
        "conn": conn,
        "invite": invite,
        "acceptance": acceptance,
        "inviter_priv": inviter_priv,
        "keys_dir": str(tmp_path / "keys"),
        "slots": {
            "inviter_send_slot": "slot-a",
            "inviter_receive_slot": "slot-b",
        },
    }


def _commit(ceremony, relay_url):
    return commit_pairing(
        ceremony["conn"],
        ceremony["acceptance"],
        ceremony["inviter_priv"],
        relay_url,
        ceremony["slots"],
        ["chat"],
        keys_dir=ceremony["keys_dir"],
    )


def _invite_state(ceremony):
    row = ceremony["conn"].execute(
        "SELECT state FROM invites WHERE invite_id = ?",
        (ceremony["invite"]["invite_id"],),
    ).fetchone()
    return row["state"]


@pytest.mark.parametrize(
    "hostile",
    [
        "http://evil.example/relay",
        "javascript:alert(1)",
        "ftp://files.example/x",
        "",
    ],
)
def test_hostile_relay_url_rejected_through_commit(ceremony, hostile):
    """The real commit path rejects hostile relay URLs with a stable code.

    ``_check_relay_url`` runs before any database write, so the rejection
    creates no relationship row, writes no relationship key file, and
    leaves the invite in its pre-commit ``accepted`` state."""
    with pytest.raises(PairingError) as exc:
        _commit(ceremony, hostile)
    assert exc.value.code == "bad_relay_url"
    assert ceremony["conn"].execute(
        "SELECT COUNT(*) FROM relationships"
    ).fetchone()[0] == 0
    assert _invite_state(ceremony) == "accepted"
    import os

    keys_dir = ceremony["keys_dir"]
    assert not os.path.exists(keys_dir) or os.listdir(keys_dir) == []


def test_valid_relay_url_commits_through_commit(ceremony):
    """Positive control: the same ceremony commits with a valid URL."""
    commit = _commit(ceremony, "https://github.com/example-org/relay.git")
    assert commit["repository_url"] == "https://github.com/example-org/relay.git"
    assert ceremony["conn"].execute(
        "SELECT COUNT(*) FROM relationships"
    ).fetchone()[0] == 1
    assert _invite_state(ceremony) == "committed"


def test_credential_embedded_url_rejected_by_cli_transport_inference():
    """The model-layer check is prefix-only, so a credential-embedded URL
    passes it; the CLI then refuses it at transport inference because it
    is not a github.com relay URL. This pins the layered behavior."""
    from muse_agent_social.cli import CliError, _infer_transport
    from muse_agent_social.model.invites import _check_relay_url

    url = "https://user:pass@github.com/example-org/relay.git"
    assert _check_relay_url(url) == url  # prefix check passes
    args = argparse.Namespace(transport=None, local_relay_dir=None)
    with pytest.raises(CliError) as exc:
        _infer_transport(args, url)
    assert exc.value.code == "bad_args"
