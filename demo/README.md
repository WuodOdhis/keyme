# KeyMe PSCT air-gap demo

Open `ckb-airgap-demo.html` in a browser. It is self-contained: no external scripts, fonts or images.

Live: https://wuododhis.github.io/keyme/demo/ckb-airgap-demo.html

Controls: previous / next, auto-play, `Malware: swap change`, reset.

This is a concept simulation, not the protocol. The QR grid is illustrative; the real verifier is the PSCT test suite. The automatic block is the change-output check: change must return to the signer's own lock. A recipient swap is the human check: the device shows the real destination and the user compares it.

Assets:

- `ckb-airgap-demo.gif` — normal flow (44 frames)
- `ckb-airgap-demo-tamper.gif` — changed-output tamper, audit failed, no signature
- `ckb-airgap-demo-poster.png` — tamper audit still
- `ckb-airgap-demo-normal.png` — normal audit still
