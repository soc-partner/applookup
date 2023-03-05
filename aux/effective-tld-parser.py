import sys, re, urllib.request

zone2 = []
zone3 = []
zone4 = []
zone5 = []

# Open and read the public suffix list from the URL
for line in urllib.request.urlopen("https://publicsuffix.org/list/public_suffix_list.dat"):
  line = line.decode('utf-8')
  # Zone5
  if re.search('^((\w|\-)+|\*)\.(\w|\-)+\.(\w|\-)+\.(\w|\-)+\.(\w|\-)+$', line, re.ASCII):
    zone5.append(line.strip()
      .replace('.', '\.')
      .replace('*', '[^.]+')
    )
  # Zone4
  elif re.search('^((\w|\-)+|\*)\.(\w|\-)+\.(\w|\-)+\.(\w|\-)+$', line, re.ASCII):
    zone4.append(line.strip()
      .replace('.', '\.')
      .replace('*', '[^.]+')
    )
  # Zone3
  elif re.search('^((\w|\-)+|\*)\.(\w|\-)+\.(\w|\-)+$', line, re.ASCII):
    zone3.append(line.strip()
      .replace('.', '\.')
      .replace('*', '[^.]+')
    )
  # Zone2
  elif re.search('^((\w|\-)+|\*)\.(\w|\-)+$', line, re.ASCII):
    zone2.append(line.strip()
      .replace('.', '\.')
      .replace('*', '[^.]+')
    )

# Write the effective TLDs to a Zeek const
with open('effective-tld.zeek', 'w') as f:
  f.write('module EffectiveName;' + '\n')
  f.write('\n')
  f.write('const effective_tlds_1st_level: pattern = /DEFINED_BELOW/ &redef;' + '\n')
  f.write('const effective_tlds_2nd_level: pattern = /DEFINED_BELOW/ &redef;' + '\n')
  f.write('const effective_tlds_3rd_level: pattern = /DEFINED_BELOW/ &redef;' + '\n')
  f.write('const effective_tlds_4th_level: pattern = /DEFINED_BELOW/ &redef;' + '\n')
  f.write('const effective_tlds_5th_level: pattern = /DEFINED_BELOW/ &redef;' + '\n')
  f.write('\n')
  f.write('redef effective_tlds_2nd_level +=\n')
  f.write('\t/\.(' + "|".join(zone2) + ')$/;' + '\n')
  f.write('\n')
  f.write('redef effective_tlds_3rd_level +=\n')
  f.write('\t/\.(' + "|".join(zone3) + ')$/;' + '\n')
  f.write('\n')
  f.write('redef effective_tlds_4th_level +=\n')
  f.write('\t/\.(' + "|".join(zone4) + ')$/;' + '\n')
  f.write('\n')
  f.write('redef effective_tlds_5th_level +=\n')
  f.write('\t/\.(' + "|".join(zone5) + ')$/;' + '\n')
  f.write('\n')

