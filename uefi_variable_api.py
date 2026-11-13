
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ctypes
from ctypes import wintypes
import os
import sys
import uuid


EFIVARS_DIR = Path("/sys/firmware/efi/efivars")

EFI_GLOBAL_VARIABLE_GUID = uuid.UUID(
    "8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

EFI_IMAGE_SECURITY_DATABASE_GUID = uuid.UUID(
    "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

# Windows error codes
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_FUNCTION = 1
ERROR_NOT_SUPPORTED = 50
ERROR_ENVVAR_NOT_FOUND = 203
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_PRIVILEGE_NOT_HELD = 1314

MAX_VARIABLE_SIZE = 1024 * 1024


class UEFIVariableError(Exception):
    """Base class for UEFI variable access errors."""


class UEFINotSupportedError(UEFIVariableError):
    """The platform or firmware interface does not support this API."""


class UEFIVariableNotFoundError(UEFIVariableError):
    """The requested variable does not exist."""


class UEFIVariableAccessError(UEFIVariableError):
    """The variable exists but could not be read."""


@dataclass(frozen=True)
class UEFIVariable:
    name: str
    vendor_guid: uuid.UUID
    attributes: int
    data: bytes


def _normalise_guid(vendor_guid: uuid.UUID | str) -> uuid.UUID:
    try:
        return (
            vendor_guid
            if isinstance(vendor_guid, uuid.UUID)
            else uuid.UUID(str(vendor_guid).strip("{}"))
        )
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(
            f"Invalid UEFI vendor GUID: {vendor_guid!r}"
        ) from exc


def _validate_name(name: str) -> None:
    if (
        not isinstance(name, str)
        or not name
        or "-" in name
        or "/" in name
        or "\\" in name
    ):
        raise ValueError(
            "Variable name must be non-empty and contain "
            "no path separators or hyphens."
        )


def _default_guid(name: str) -> uuid.UUID:
    if name.casefold() in {"db", "dbx"}:
        return EFI_IMAGE_SECURITY_DATABASE_GUID
    return EFI_GLOBAL_VARIABLE_GUID


class LinuxEFIVariableAPI:
    """Read UEFI variables through Linux efivarfs."""

    def __init__(self, efivars_dir: str | Path = EFIVARS_DIR):
        self.efivars_dir = Path(efivars_dir)

    def _check_supported(self) -> None:
        if not sys.platform.startswith("linux"):
            raise UEFINotSupportedError(
                "The Linux efivarfs backend can only run on Linux."
            )

        if not self.efivars_dir.is_dir():
            raise UEFINotSupportedError(
                f"efivarfs is not available at {self.efivars_dir}. "
                "Boot in UEFI mode and ensure efivarfs is mounted."
            )

    def get_variable(
        self,
        name: str,
        vendor_guid: uuid.UUID | str,
    ) -> UEFIVariable:
        _validate_name(name)
        guid = _normalise_guid(vendor_guid)
        self._check_supported()

        path = self.efivars_dir / f"{name}-{guid}"

        if not path.exists():
            raise UEFIVariableNotFoundError(
                f"UEFI variable {name} ({guid}) was not found."
            )

        try:
            raw = path.read_bytes()
        except PermissionError as exc:
            raise UEFIVariableAccessError(
                f"Permission denied reading {path}."
            ) from exc
        except OSError as exc:
            raise UEFIVariableAccessError(
                f"Could not read {path}: {exc}"
            ) from exc

        if len(raw) < 4:
            raise UEFIVariableAccessError(
                f"Variable file {path} is truncated."
            )

        attributes = int.from_bytes(raw[:4], "little")

        return UEFIVariable(
            name=name,
            vendor_guid=guid,
            attributes=attributes,
            data=raw[4:],
        )

    def enumerate_variables(
        self,
        vendor_guid: uuid.UUID | str | None = None,
    ) -> list[str]:
        self._check_supported()

        guid_text = (
            str(_normalise_guid(vendor_guid)).lower()
            if vendor_guid is not None
            else None
        )

        names = []

        try:
            for path in self.efivars_dir.iterdir():
                if not path.is_file() or "-" not in path.name:
                    continue

                name, suffix = path.name.split("-", 1)

                if guid_text is None or suffix.lower() == guid_text:
                    names.append(name)

        except OSError as exc:
            raise UEFIVariableAccessError(
                f"Could not enumerate {self.efivars_dir}: {exc}"
            ) from exc

        return sorted(set(names))


import ctypes
from ctypes import wintypes


def enable_firmware_privilege():
    """Enable SeSystemEnvironmentPrivilege for this process."""

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002
    ERROR_NOT_ALL_ASSIGNED = 1300

    class LUID(ctypes.Structure):
        _fields_ = [
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
        ]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Luid", LUID),
            ("Attributes", wintypes.DWORD),
        ]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    advapi32 = ctypes.WinDLL(
        "advapi32.dll",
        use_last_error=True
    )

    kernel32 = ctypes.WinDLL(
        "kernel32.dll",
        use_last_error=True
    )

    # Explicit Windows API declarations (important on 64-bit Windows).

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
    ]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    token = wintypes.HANDLE()

    process = kernel32.GetCurrentProcess()

    if not advapi32.OpenProcessToken(
        process,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        luid = LUID()

        if not advapi32.LookupPrivilegeValueW(
            None,
            "SeSystemEnvironmentPrivilege",
            ctypes.byref(luid),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)

        if not advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(privileges),
            0,
            None,
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        error = ctypes.get_last_error()

        if error == ERROR_NOT_ALL_ASSIGNED:
            raise PermissionError(
                "SeSystemEnvironmentPrivilege is not assigned "
                "to this account. Check Windows User Rights Assignment."
            )

        if error:
            raise ctypes.WinError(error)

    finally:
        kernel32.CloseHandle(token)

    return True

class WindowsFirmwareVariableAPI:
    """
    Read UEFI variables using the native Windows firmware API.

    Uses GetFirmwareEnvironmentVariableExW.

    No firmware variables are written or deleted.
    """

    def __init__(self):
        enable_firmware_privilege()
        if os.name != "nt":
            raise UEFINotSupportedError(
                "The Windows firmware backend can only run on Windows."
            )

        try:
            self.kernel32 = ctypes.WinDLL(
                "kernel32",
                use_last_error=True,
            )

            self._get_variable = (
                self.kernel32.GetFirmwareEnvironmentVariableExW
            )

            self._get_variable.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ]

            self._get_variable.restype = ctypes.c_uint32

        except (AttributeError, OSError) as exc:
            raise UEFINotSupportedError(
                "Windows firmware variable APIs are unavailable."
            ) from exc

    def _raise_windows_error(
        self,
        name: str,
        guid: uuid.UUID,
        error_code: int,
    ) -> None:

        if error_code == ERROR_ENVVAR_NOT_FOUND:
            raise UEFIVariableNotFoundError(
                f"UEFI variable {name} ({guid}) was not found."
            )

        if error_code in (
            ERROR_INVALID_FUNCTION,
            ERROR_NOT_SUPPORTED,
        ):
            raise UEFINotSupportedError(
                "Windows firmware variable access is unavailable. "
                "The system may not have booted in UEFI mode."
            )

        if error_code in (
            ERROR_ACCESS_DENIED,
            ERROR_PRIVILEGE_NOT_HELD,
        ):
            raise UEFIVariableAccessError(
                "Access denied reading the firmware variable. "
                "The process may require "
                "SeSystemEnvironmentPrivilege."
            )

        raise UEFIVariableAccessError(
            f"Windows firmware API failed with error "
            f"{error_code} for {name} ({guid})."
        )

    def get_variable(
        self,
        name: str,
        vendor_guid: uuid.UUID | str,
    ) -> UEFIVariable:

        _validate_name(name)
        guid = _normalise_guid(vendor_guid)

        # Windows expects the GUID in standard textual form.
        guid_text = "{" + str(guid) + "}"

        buffer_size = 4096

        while buffer_size <= MAX_VARIABLE_SIZE:

            buffer = ctypes.create_string_buffer(buffer_size)
            attributes = ctypes.c_uint32(0)

            ctypes.set_last_error(0)

            result = self._get_variable(
                name,
                guid_text,
                buffer,
                buffer_size,
                ctypes.byref(attributes),
            )

            if result != 0:
                return UEFIVariable(
                    name=name,
                    vendor_guid=guid,
                    attributes=attributes.value,
                    data=buffer.raw[:result],
                )

            error_code = ctypes.get_last_error()

            if error_code == ERROR_INSUFFICIENT_BUFFER:
                buffer_size *= 2
                continue

            self._raise_windows_error(
                name,
                guid,
                error_code,
            )

        raise UEFIVariableAccessError(
            f"UEFI variable {name} exceeds the "
            f"maximum supported size of {MAX_VARIABLE_SIZE} bytes."
        )

    def enumerate_variables(
        self,
        vendor_guid: uuid.UUID | str | None = None,
    ) -> list[str]:

        raise UEFINotSupportedError(
            "Windows does not provide a documented equivalent "
            "of Linux efivarfs directory enumeration through "
            "GetFirmwareEnvironmentVariableExW."
        )


def get_firmware_variable(
    name: str,
    vendor_guid: uuid.UUID | str | None = None,
    efivars_dir: str | Path = EFIVARS_DIR,
) -> UEFIVariable:
    """
    Cross-platform read-only UEFI variable access.

    Linux: Linux efivarfs.
    Windows: GetFirmwareEnvironmentVariableExW.

    If vendor_guid is omitted:
      PK, KEK, SecureBoot, SetupMode, dbx, etc. use
      their appropriate namespace only when explicitly
      handled by the caller or the default mapping.
    """

    _validate_name(name)

    guid = (
        _normalise_guid(vendor_guid)
        if vendor_guid is not None
        else _default_guid(name)
    )

    if sys.platform.startswith("linux"):
        backend = LinuxEFIVariableAPI(efivars_dir)

    elif os.name == "nt":
        backend = WindowsFirmwareVariableAPI()

    else:
        raise UEFINotSupportedError(
            f"Unsupported operating system: {sys.platform}"
        )

    return backend.get_variable(name, guid)
