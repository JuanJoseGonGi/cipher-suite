import click
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_pem_public_key,
)
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.markdown import Markdown

# Console for styled printing
console = Console()


def print_cli_description():
    description = """
    [bold green]Encryption Suite CLI[/bold green]

    Implements various cryptographic functions including hashing, RSA signature,
    RSA encryption, and signing/verifying with elliptic curve cryptography.
    """
    console.print(Markdown(description))


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Encryption Suite CLI"""
    if ctx.invoked_subcommand is None:
        print_cli_description()


@cli.command()
@click.argument("message")
def hash(message):
    """Generate a message digest (hash) of the message."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    result = digest.finalize()
    console.print(f"[bold yellow]Message Digest:[/bold yellow] {result.hex()}")


@cli.command()
@click.argument("message")
def sign_rsa(message):
    """Generate a digital RSA signature of the message."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    console.print("[bold blue]RSA Signature Generated:[/bold blue]", signature.hex())


@cli.command()
@click.argument("message")
def encrypt_rsa(message):
    """Encrypt a message using RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    console.print(
        "[bold magenta]RSA Encrypted Message:[/bold magenta]", encrypted_message.hex()
    )


@cli.command()
@click.argument("message")
@click.option(
    "--private-key-file", "-p", type=click.Path(), default="ec_private_key.pem"
)
@click.option("--public-key-file", "-u", type=click.Path(), default="ec_public_key.pem")
@click.option("--signature-file", "-s", type=click.Path(), default="ec_signature.txt")
def sign_ec(message, private_key_file, public_key_file, signature_file):
    """Sign a message using elliptic curve cryptography and save keys."""
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
            )
        )

    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )

    signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))

    with open(signature_file, "wb") as f:
        f.write(signature)

    console.print("[bold green]EC Signature Generated and Saved:[/bold green]")
    console.print(f"[bold green]Signature:[/bold green] {signature.hex()}")


@cli.command()
@click.argument("message")
@click.option(
    "--signature-file", "-s", type=click.Path(exists=True), default="ec_signature.txt"
)
@click.option(
    "--public-key-file", "-u", type=click.Path(exists=True), default="ec_public_key.pem"
)
def verify_ec(message, signature_file, public_key_file):
    """Verify a signature with elliptic curve cryptography."""
    try:
        with open(signature_file, "rb") as sig_file:
            signature = sig_file.read()

        with open(public_key_file, "rb") as pub_file:
            public_key_data = pub_file.read()

        public_key = load_pem_public_key(public_key_data, backend=default_backend())
        public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        console.print("[bold green]Message Verified![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Message Verification Failed! Error: {e}[/bold red]")


if __name__ == "__main__":
    cli()
