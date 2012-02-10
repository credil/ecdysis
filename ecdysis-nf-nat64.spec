# "uname -r" output of the kernel to build for, the running one
# if none was specified with "--define 'kernel '"
#%{!?kernel: %{expand: %%define kernel %(uname -r)}}
%define kernelver %(uname -r | sed -r 's/\.[^.]+$//')

Summary: NAT64 linux module
Name: ecdysis-nf-nat64
Version: 20101117
Release: 1%{?dist}
License: GPLv3
Url: http://ecdysis.viagenie.ca/
Source: http://ecdysis.viagenie.ca/download/%{name}-%{version}.tar.gz

Group: Networking
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: kernel = %{kernelver}
BuildRequires: kernel-devel = %{kernelver}

%description
NAT64 linux module

%prep
%setup -q 

%build
%{__make} CFLAGS="$RPM_OPT_FLAGS" QUIET=no 

%install
%{__rm} -rf %{buildroot}
%{__mkdir} %{buildroot}

%{__mkdir_p} %{buildroot}/lib/modules/%{kernel}/extra
%{__install} -Dp -m0644 nf_nat64.ko \
    %{buildroot}/lib/modules/%{kernel}/extra

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-, root, root, 0755)
/lib/modules/%{kernel}/extra/
%doc COPYING README CHANGES KNOWN_ISSUES nat64-config.sh

%post 
/sbin/depmod -a -F /boot/System.map-%{kernel} %{kernel} &>/dev/null || :

%postun 
/sbin/depmod -a -F /boot/System.map-%{kernel} %{kernel} &>/dev/null || :

%changelog
* Tue Feb 23 2010 Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca> 0.1.1-1
- Initial spec file

