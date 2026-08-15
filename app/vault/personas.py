"""Persona credential vault.

You cannot test Broken Object Level Authorization with a single identity. BOLA
means "user A can reach user B's object" — that requires *two* real, distinct
identities plus knowledge of what each legitimately owns. The vault holds those
identities and their auth material; test cases reference personas by name so a
secret never lives inside a test case or a report.

MVP loads personas from a local file / env. In production this backs onto a
real secret store (Vault, cloud secret manager) — the interface stays the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Persona:
    name: str
    # A ready-to-use header map, e.g. {"Authorization": "Bearer eyJ..."}.
    # Empty for the `anonymous` persona.
    auth_headers: dict[str, str] = field(default_factory=dict)
    role: str = "user"
    # Object ids this persona legitimately owns — used to build BOLA cases
    # (A attacks an object owned by B) and to verify leaks by known markers.
    owns: dict[str, str] = field(default_factory=dict)  # {"customer_id": "2002"}
    # Known sensitive values that must NOT appear in another persona's response.
    secret_markers: list[str] = field(default_factory=list)  # e.g. B's email


class PersonaVault:
    def __init__(self, personas: list[Persona] | None = None) -> None:
        self._personas: dict[str, Persona] = {}
        for p in personas or []:
            self.add(p)
        # `anonymous` always exists — the un-authenticated identity.
        if "anonymous" not in self._personas:
            self.add(Persona(name="anonymous"))

    def add(self, persona: Persona) -> None:
        self._personas[persona.name] = persona

    def get(self, name: str) -> Persona:
        try:
            return self._personas[name]
        except KeyError:
            raise KeyError(
                f"Persona '{name}' is not defined in the vault. Add it before "
                f"running a test that references it."
            ) from None

    def names(self) -> list[str]:
        return list(self._personas)
