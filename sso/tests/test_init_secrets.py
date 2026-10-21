"""scripts/init_secrets.sh (compose "init" service): keys and bootstrap certificate when their folders are empty."""
import os
import shutil
import stat
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "scripts", "init_secrets.sh")

pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("openssl")), reason="needs bash + openssl")


@pytest.fixture
def run(tmp_path):
    keys, certs = tmp_path / "keys", tmp_path / "certs"

    def _run(**kw):
        env = {
            "PATH": os.environ["PATH"],
            "INIT_KEYS_DIR": str(keys), "INIT_CERTS_DIR": str(certs),
            "SSO_UID": str(os.getuid()), "SSO_GID": str(os.getgid()),
            "SSO_HOSTNAME": "sso.acme.test",
            "SSO_JWT_PRIVATE_KEY": "k1.private.pem", "SSO_JWT_PUBLIC_KEYS": "k1.public.pem",
            "SSO_TLS_CERT_FILE": "selfsigned.crt", "SSO_TLS_KEY_FILE": "selfsigned.key",
        }
        env.update(kw)
        return subprocess.run(["bash", SCRIPT], capture_output=True, text=True, env=env, timeout=120)
    _run.keys, _run.certs = keys, certs
    return _run


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_empty_folders_generate_everything(run):
    p = run()
    assert p.returncode == 0, p.stderr
    assert "NEW key pair" in p.stderr
    assert mode(run.keys / "k1.private.pem") == 0o600 and mode(run.keys / "k1.public.pem") == 0o644
    if os.getuid() == 0:
        assert mode(run.keys) == 0o700
    crt = run.certs / "selfsigned.crt"
    assert crt.exists() and (run.certs / "selfsigned.key").exists()
    out = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-checkhost", "sso.acme.test"],
                         capture_output=True, text=True).stdout
    assert "does match" in out
    # second run: no-op
    before = (run.keys / "k1.private.pem").read_bytes()
    p = run()
    assert p.returncode == 0 and "NEW" not in p.stderr
    assert (run.keys / "k1.private.pem").read_bytes() == before


def test_configured_cert_names_and_ip(run):
    p = run(SSO_HOSTNAME="192.168.0.212", SSO_TLS_CERT_FILE="fullchain.pem", SSO_TLS_KEY_FILE="privkey.pem",
            SSO_TLS_REJECT_UNKNOWN_SNI="on")
    assert p.returncode == 0, p.stderr
    assert "SSO_TLS_REJECT_UNKNOWN_SNI is not off" in p.stderr
    out = subprocess.run(["openssl", "x509", "-in", run.certs / "fullchain.pem", "-noout", "-checkip",
                          "192.168.0.212"], capture_output=True, text=True).stdout
    assert "does match" in out


def test_existing_selfsigned_for_other_host_warns_and_is_kept(run):
    assert run().returncode == 0
    before = (run.certs / "selfsigned.crt").read_bytes()
    p = run(SSO_HOSTNAME="other.acme.test")
    assert p.returncode == 0 and "does not cover SSO_HOSTNAME=other.acme.test" in p.stderr
    assert (run.certs / "selfsigned.crt").read_bytes() == before


def test_non_empty_key_folder_with_missing_file_fails(run):
    assert run().returncode == 0
    p = run(SSO_JWT_PUBLIC_KEYS="k0.public.pem,k1.public.pem")
    assert p.returncode == 1 and "missing: k0.public.pem" in p.stderr
    p = run(SSO_JWT_PRIVATE_KEY="k2.private.pem", SSO_JWT_PUBLIC_KEYS="k2.public.pem")
    assert p.returncode == 1 and "nothing generated" in p.stderr
    assert not (run.keys / "k2.private.pem").exists()


def test_empty_folder_with_rotation_list_refuses(run):
    p = run(SSO_JWT_PUBLIC_KEYS="k0.public.pem,k1.public.pem")
    assert p.returncode == 1 and "lost" in p.stderr
    assert not run.keys.exists() or not list(run.keys.iterdir())


@pytest.mark.parametrize("kw, needle", [
    ({"SSO_JWT_PRIVATE_KEY": ""}, "SSO_JWT_PRIVATE_KEY is empty"),
    ({"SSO_JWT_PUBLIC_KEYS": ""}, "SSO_JWT_PUBLIC_KEYS is empty"),
    ({"SSO_JWT_PRIVATE_KEY": "/run/keys/k1.private.pem"}, "plain file name"),
    ({"SSO_JWT_PRIVATE_KEY": "k1.pem"}, "plain file name"),
])
def test_bad_key_names(run, kw, needle):
    p = run(**kw)
    assert p.returncode == 1 and needle in p.stderr


def test_letsencrypt_path_is_not_generated(run):
    p = run(SSO_TLS_CERT_FILE="live/sso.acme.test/fullchain.pem", SSO_TLS_KEY_FILE="live/sso.acme.test/privkey.pem")
    assert p.returncode == 1 and "Let's Encrypt" in p.stderr


def test_half_a_cert_pair_fails(run):
    run.certs.mkdir()
    (run.certs / "selfsigned.crt").write_text("x")
    p = run()
    assert p.returncode == 1 and "only one of" in p.stderr


def test_auto_init_false_only_checks(run):
    p = run(SSO_AUTO_INIT="false")
    assert p.returncode == 1 and "SSO_AUTO_INIT=false" in p.stderr
    assert not list(run.keys.glob("*.pem"))
    assert run().returncode == 0
    os.remove(run.certs / "selfsigned.crt")
    os.remove(run.certs / "selfsigned.key")
    p = run(SSO_AUTO_INIT="false")
    assert p.returncode == 1 and "selfsigned.crt missing" in p.stderr


def test_missing_hostname_for_cert(run):
    p = run(SSO_HOSTNAME="")
    assert p.returncode == 1 and "SSO_HOSTNAME is empty" in p.stderr
