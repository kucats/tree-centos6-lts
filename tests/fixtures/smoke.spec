Name: tree-centos6-lts-smoke
Version: 0.1
Release: 1%{?dist}
Summary: Legacy CentOS RPM build smoke test
License: MIT
BuildArch: noarch
Source0: hello.sh

%description
A trivial package for testing RPM tooling, not a security update.

%prep

%build

%install
mkdir -p %{buildroot}%{_bindir}
install -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/tree-centos6-lts-smoke

%files
%{_bindir}/tree-centos6-lts-smoke

%changelog
* Thu Oct 22 2026 tree-centos6-lts contributors <noreply@example.invalid> - 0.1-1
- Initial smoke-test package
