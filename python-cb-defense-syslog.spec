%define name python-cb-defense-syslog
%define version 1.2
%define unmangled_version 1.2
%define release 8
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Cb Defense Syslog
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: Commercial
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black Developer Network<dev-support@carbonblack.com>
Url: https://developer.carbonblack.com

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-defense-syslog.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%posttrans
mkdir -p /usr/share/cb/integrations/cb-defense-syslog/store
mkdir -p /etc/cb/integrations/cb-defense-syslog
mkdir -p /var/log/cb/integrations/cb-defense-syslog

%preun

%files -f INSTALLED_FILES
%defattr(-,root,root)
