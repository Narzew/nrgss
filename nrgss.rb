# For latest version see : https://dl.dropbox.com/u/98829851/%C5%B9r%C3%B3d%C5%82owe/nrgss.rb
# http://hacktut.org
# http://twitter.com/narzew
#===========================================================
#**NRGSS (Narzew RGSS Module)
#**Narzew
#**Version 2.5
#===========================================================
#**History:
#**11.05.12 - 1.0
#**20.05.12 - 1.1
#**1.06.12 - 1.2
#**3.06.12 - 1.3
#**10.06.12 - 1.4
#**22.06.12 - 1.5
#**13.07.12 - 1.6
#**27.07.12 - 1.7
#**09.08.12 - 1.8
#**24.08.12 - 1.9
#**26.08.12 - 2.0
#**29.08.12 - 2.1
#**4.09.12 - 2.2
#**8.09.12 - 2.3
#**18.09.12 - 2.4
#**06.10.12 - 2.5
#===========================================================

#===========================================================
#**Module Authors:
#**Narzew
#**Peter O.
#**A Crying Minister
#**Forever Zer0
#**KGC
#===========================================================

#===========================================================
#**Start of Library
#**Początek biblioteki
#===========================================================

#===========================================================
#**NRGSS Class
#**Klasa główna NRGSS
#===========================================================

class NRGSS
  
  #===========================================================
  #**initialize
  #**Defines a initialisation of class
  #**Definiuje inicjalizację klasy
  #**Narzew
  #===========================================================
  
  def initialize
    $nrgss_version = 2.5
  end
  
  #===========================================================
  #**version
  #**Defines a library Version
  #**Definiuje wersję biblioteki
  #**Narzew
  #===========================================================
  
  def version
    return $nrgss_version
  end
  
  #===========================================================
  #**Variable definitions
  #**Definicje zmiennych
  #**Narzew
  #===========================================================

  $error_section_num = (/^(?:Section)?{?(\d+)}?:/)
  $error_section = (/^(?:Section)?{?\d+}?:/)
  $double_crlf = (/\n\n/)
  $line = "\n"
  $doubleline = "\n\n"
  
  $messagebox = Win32API.new('user32', 'MessageBoxA', %w(p p p i), 'i')
  $msgbox = Win32API.new('user32', 'MessageBoxA', %w(p p p i), 'i')
  $getprivateprofilestring = Win32API.new('kernel32', 'GetPrivateProfileStringA',%w(p p p p l p),'l')
  $mcisendstring = Win32API.new('winmm', 'mciSendString', 'PPLL', 'L')
  $midioutsetvolume = Win32API.new('winmm', 'midiOutSetVolume', 'LL', 'L')
  
  $halfbyte = 0xF
  $byte = 0xFF
  $doublebyte = 0xFFFF
  $threebyte = 0xFFFFFF
  $long = 0xFFFFFF
  $hex = 0xF
  $hex2 = $byte
  $hex4 = $doublebyte
  $hex8 = $long
  $hex16 = 0xFFFFFFFFFFFFFFFF
  $hex32 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  $hex48 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  $hex64 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  $hexes = [16**0,16**1,16**2,16**3,16**4,16**5,16**6,16**7,16**8,16**9,16**10,16**11,16**12,16**13,16**14,16**15,16**16]
  
  $registered_names = []
  $registered_authors = []
  $registered_scripts = {}
  
  #===========================================================
  #**register
  #**Registers a component
  #**Rejestruje komponent
  #**Narzew
  #===========================================================
  
  def register(product, author, version)
    $registered_scripts[product] =  [author, version]
    $registered_authors << author
    $registered_names << product
  end
  
  #===========================================================
  #**registered?(product)
  #**Checks the component is registered
  #**Sprawdza czy komponent jest zarejestrowany
  #**Narzew
  #===========================================================
  
  def registered?(product, rd=false)
    if $registered_scripts.include?(product)
      if rd
        return $registered_scripts[product]
      else
        return true
      end
    else
      return false
    end
  end
  
  #===========================================================
  #**check_version(product, version)
  #**Checks the component is in valid version
  #**Sprawdza czy komponent jest w poprawnej wersji
  #===========================================================
  
  def check_version(product, version, raise=0)
    return false unless registered?(product)
    if $registered_scripts[product][1] >= version
      return true
    else
      raise("Bad version of product : #{product}.\nVersion : #{version} or later is required.") if raise == 1
      return false
    end
  end
  
  #===========================================================
  #**in_range?
  #**Checks the value is between x and y
  #**Sprawdza czy wartość jest pomiedzy x a y
  #**Narzew
  #===========================================================
  
  def in_range?( x, y, value)
    value = self if value ==  nil
    return true if value.to_i > x.to_i and value < y.to_i
  end
  
  #===========================================================
  #**round_range
  #**Rounds the value to range
  #**Zaokrągla wartość do zasięgu
  #**Narzew
  #===========================================================
  
  def round_range(min, max, value)
    value = self if value == nil
    if value > max
      value = max
    elsif value < min
      value = min
    end
    return value
  end
  
  #===========================================================
  #**unpack_byte
  #**Unpacks byte to letter
  #**Odpakowuje bajt do litery
  #**Narzew
  #===========================================================
  
  def unpack_byte(byte)
    result  = []
    case byte
    when 0 then result << '$NULL$'
    when 1 then result << '$SOH$'
    when 2 then result << '$STX$'
    when 3 then result << '$ETX$'
    when 4 then result << '$EOT$'
    when 5 then result << '$ENQ$'
    when 6 then result << '$ACK$'
    when 7 then result << '$BEL$'
    when 8 then result << '$BS$'
    when 9 then result << '$TAB$'
    when 10 then result << '$LF$'
    when 11 then result << '$VT$'
    when 12 then result << '$FF$'
    when 13 then result << '$CR$'
    when 14 then result << '$SO$'
    when 15 then result << '$SI$'
    when 16 then result << '$DLE$'
    when 17 then result << '$DC1$'
    when 18 then result << '$DC2$'
    when 19 then result << '$DC3$'
    when 20 then result << '$DC4$'
    when 21 then result << '$NAK$'
    when 22 then result << '$SYN$'
    when 23 then result << '$ETB$'
    when 24 then result << '$CAN$'
    when 25 then result << '$EN$'
    when 26 then result << '$SUB$'
    when 27 then result << '$ESC$'
    when 28 then result << '$FS$'
    when 29 then result << '$GS$'
    when 30 then result << '$RS$'
    when 31 then result << '$US$'
    when 32 then result << ' '
    when 33 then result << '!'
    when 34 then result << '\"'
    when 35 then result << '#'
    when 36 then result << '$'
    when 37 then result << '%'
    when 38 then result << '&'
    when 39 then result << '\''
    when 40 then result << '('
    when 41 then result << ')'
    when 42 then result << '*'
    when 43 then result << '+'
    when 44 then result << ','
    when 45 then result << '-'
    when 46 then result << '.'
    when 47 then result << '/'
    when 48 then result << '0'
    when 49 then result << '1'
    when 50 then result << '2'
    when 51 then result << '3'
    when 52 then result << '4'
    when 53 then result << '5'
    when 54 then result << '6'
    when 55 then result << '7'
    when 56 then result << '8'
    when 57 then result << '9'
    when 58 then result << ':'
    when 59 then result << ';'
    when 60 then result << '<'
    when 61 then result << '='
    when 62 then result << '>'
    when 63 then result << '?'
    when 64 then result << '@'
    when 65 then result << 'A'
    when 66 then result << 'B'
    when 67 then result << 'C'
    when 68 then result << 'D'
    when 69 then result << 'E'
    when 70 then result << 'F'
    when 71 then result << 'G'
    when 72 then result << 'H'
    when 73 then result << 'I'
    when 74 then result << 'J'
    when 75 then result << 'K'
    when 76 then result << 'L'
    when 77 then result << 'M'
    when 78 then result << 'N'
    when 79 then result << 'O'
    when 80 then result << 'P'
    when 81 then result << 'Q'
    when 82 then result << 'R'
    when 83 then result << 'S'
    when 84 then result << 'T'
    when 85 then result << 'U'
    when 86 then result << 'V'
    when 87 then result << 'W'
    when 88 then result << 'X'
    when 89 then result << 'Y'
    when 90 then result << 'Z'
    when 91 then result << '['
    when 92 then result << '\\'
    when 93 then result << ']'
    when 94 then result << '^'
    when 95 then result << '_'
    when 96 then result << '`'
    when 97 then result << 'a'
    when 98 then result << 'b'
    when 99 then result << 'c'
    when 100 then result << 'd'
    when 101 then result << 'e'
    when 102 then result << 'f'
    when 103 then result << 'g'
    when 104 then result << 'h'
    when 105 then result << 'i'
    when 106 then result << 'j'
    when 107 then result << 'k'
    when 108 then result << 'l'
    when 109 then result << 'm'
    when 110 then result << 'n'
    when 111 then result << 'o'
    when 112 then result << 'p'
    when 113 then result << 'q'
    when 114 then result << 'r'
    when 115 then result << 's'
    when 116 then result << 't'
    when 117 then result << 'u'
    when 118 then result << 'v'
    when 119 then result << 'w'
    when 120 then result << 'x'
    when 121 then result << 'y'
    when 122 then result << 'z'
    when 123 then result << '{'
    when 124 then result << '|'
    when 125 then result << '}'
    when 126 then result << '~'
    when 127 then result << '$DEL$'
    else
      result << '$NOT$'
    end
    return result
  end
  
  #===========================================================
  #**unpack_clear_byte
  #**Unpacks clear (>32) byte
  #**Depakowuje czysty (>32) bajt
  #**Narzew
  #===========================================================
  
  def unpack_clear_byte(byte)
    if byte <= 31
      byte = 32
    end
    $nrgss.unpack_byte(byte)
  end
  
  #===========================================================
  #**unpack_text
  #**Unpacks byte packed text (array)
  #**Odpakowuje tekst zapisany w tablicy bajtów
  #**Narzew
  #===========================================================
  
  def unpack_text(texttabl)
    result = []
    texttabl.each{|byte|
    result << $nrgss.unpack_byte(byte)
    }
    return result.to_s
  end
  
  #===========================================================
  #**pack_bytes
  #**Packs bytes to array from text
  #**Pakuje bajty do tablicy z tekstu
  #**Narzew
  #===========================================================
  
  def pack_bytes(text)
    result = []
    text.each_byte{|byte| result << byte }
    return result
  end
  
  #===========================================================
  #**pack_byte
  #**Packs one byte to array from text
  #**Pakuje pojedyńczy bajt do tablicy z tekstu
  #**Narzew
  #===========================================================
  
  def pack_byte(letter)
    result = []
    letter.each_byte{|byte| result << letter }
    return result.at(0)
  end
  
  #===========================================================
  #**encrypt_int
  #**Encrypts an int
  #**Koduje liczbę
  #**Narzew
  #===========================================================
  
  def encrypt_int(int, key=17)
	srand(key * 7 + 3)
	return rand(9999) + int
  end
  
  #===========================================================
  #**decrypt_int
  #**Decrypts an int
  #**Dekoduje liczbę
  #**Narzew
  #===========================================================
  
  def decrypt_int(int, key=17)
	srand(key * 7 + 3)
	return int - rand(9999)
  end
  
  #===========================================================
  #**file_read
  #**Reads file
  #**Odczytuje plik
  #**Narzew
  #===========================================================
  
  def file_read(file2)
    file = File.open(file2, 'rb')
    return file.read
  end
  
  #===========================================================
  #**file_write
  #**Writes file
  #**Zapisuje plik
  #**Narzew
  #===========================================================
  
  def file_write(var, file2)
    file = File.open(file2, 'wb')
    file.write(var)
    file.close
  end
  
  #===========================================================
  #**file_dump
  #**Dumps to file
  #**Zapisuje dane binarne do pliku
  #**Narzew
  #===========================================================
  
  def file_dump(var, file2)
    file = File.open(file2, 'wb')
    Marshal.dump(var, file)
    file.close
  end
  
  #===========================================================
  #**file_link
  #**Links two files
  #**Łączy dwa pliki
  #**Narzew
  #===========================================================
  
  def file_link(afile, bfile, cfile)
    file1 = File.open(afile, 'rb')
    file2 = File.open(bfile, 'rb')
    file3 = File.open(cfile, 'wb')
    file3.write(file1.read)
    file3.write(file2.read)
    file1.close
    file2.close
    file3.close
  end
  
  #===========================================================
  #**cbrt
  #**3rd root
  #**Pierwiastek sześcienny
  #**Narzew
  #===========================================================
  
  def cbrt(x)
    result = x**(1.0/3.0)
    return result
  end
  
  #===========================================================
  #**root
  #**Root
  #**Pierwiastek
  #**Narzew
  #===========================================================
  
  def root(nr, st)
    result = nr**(1.0/st.to_f)
    return result
  end
  
  #===========================================================
  #**oppose
  #**Oppose
  #**Przeciwność
  #**Narzew
  #===========================================================
  
  def oppose(nr)
    result = nr - (nr*2)
    return result
  end
  
  #===========================================================
  #**randomize
  #**Randomize a int with range
  #**Losuje liczbę z zakresu
  #**Narzew
  #===========================================================
  
  def randomize(min, max)
    return rand(max - min + 1)
  end
  
  #===========================================================
  #**save_script
  #**Saves a RGSS scripts to text
  #**Zapisuje skrypty RGSS do tekstu
  #**Narzew
  #===========================================================
  
  def save_script(filename='script.txt', scriptfile='Data/Scripts.rxdata')
    file = File.open(filename, 'wb')
    script = load_data(scriptfile)
    script.each {|s|
    file.write(Zlib::Inflate.inflate(s.at(2)))
    file.write("\n\n\n")
    }
    file.close
  end
  
  #===========================================================
  #**Messagebox
  #**Messgebox
  #**Okienko z wiadomością
  #**A Crying Minister
  #===========================================================
  
  def messagebox(message, title, type)
    $msgbox.call(0, message, title, type)
  end
  
  #===========================================================
  #**b64_encode
  #**Encodes string using Base64 algorithm
  #**Koduje ciąg używając algorytmu Base64
  #**Narzew
  #===========================================================
  
  def b64_encode(x)
    return [x].pack('m')
  end
  
  #===========================================================
  #**b64_decode
  #**Decodes string using Base64 algorithm
  #**Dekoduje ciąg używając algorytmu Base64
  #**Narzew
  #===========================================================
  
  def b64_decode(x)
    return x.unpack('m').first
  end
  
  #===========================================================
  #**uu_encode
  #**Encodes string using UU algorithm
  #**Koduje ciąg używając algorytmu UU
  #**Narzew
  #===========================================================
  
  def uu_encode(x)
    return [x].pack('u')
  end
  
  #===========================================================
  #**uu_decode
  #**Decodes string using UU algorithm
  #**Dekoduje ciąg używając algorytmu UU
  #**Narzew
  #===========================================================
  
  def uu_decode(x)
    return x.unpack('u')
  end
  
  #===========================================================
  #**b64_encode_file
  #**Encodes file using Base64 algorithm
  #**Koduje plik używając algorytmu Base64
  #**Narzew
  #===========================================================
  
  def b64_encode_file(file, result)
    readfile = File.open(file, 'rb')
    writefile = File.open(result, 'wb')
    data = readfile.read
    writefile.write($nrgss.b64_encode(data))
    readfile.close
    writefile.close
  end
  
  #===========================================================
  #**b64_decode_file
  #**Decodes file using Base64 algorithm
  #**Dekoduje plik używając algorytmu Base64
  #**Narzew
  #===========================================================
  
  def b64_decode_file(file, result)
    readfile = File.open(file, 'rb')
    writefile = File.open(result, 'wb')
    data = readfile.read
    writefile.write($nrgss.b64_decode(data))
    readfile.close
    writefile.close
  end
  
  #===========================================================
  #**uu_encode_file
  #**Encodes file using UU algorithm
  #**Koduje plik używając algorytmu UU
  #**Narzew
  #===========================================================
  
  def uu_encode_file(file, result)
    readfile = File.open(file, 'rb')
    writefile = File.open(result, 'wb')
    data = readfile.read
    writefile.write($nrgss.uu_encode(data))
    readfile.close
    writefile.close
  end
  
  #===========================================================
  #**uu_decode_file(file, result)
  #**Decodes file using UU algorithm
  #**Dekoduje plik używając algorytmu UU
  #**Narzew
  #===========================================================
  
  def uu_decode_file(file, result)
    readfile = File.open(file, 'rb')
    writefile = File.open(result, 'wb')
    data = readfile.read
    writefile.write($nrgss.uu_decode(data))
    readfile.close
    writefile.close
  end
  
  #===========================================================
  #**uri_download
  #**Downloads file using open-uri algorithm. Clear Ruby only.
  #**Pobiera plik używając algorytmu open-uri. Tylko czyste ruby.
  #**Narzew
  #===========================================================
  
  def uri_download(x, nam)
    require 'open-uri'
    open(x) {|f|
    file = File.open(nam, 'wb')
    file.write(f.read)
    file.close
    }
  end
  
  #===========================================================
  #**location_table
  #**Gets location file list from location array
  #**Zwraca wszystkie nazwy plików z lokacji określonych w tablicy
  #**Narzew
  #===========================================================
  
  def location_table(locations_ary)
    result = []
    locations_ary.each{|location|
    Dir.foreach(location){|x|
    if x != '.'
      if x != '..'
        result << "#{location}/#{x}"
      end
    end
    }
    }
    return result
  end
  
  #===========================================================
  #**xorify_crypt
  #**Encrypts script using xorify algorithm. Only TEXT are supported.
  #**Koduje skrypt używając algorytmu xorify. Tylko TEXT jest obsługiwany.
  #**Narzew
  #===========================================================
  
  def xorify_crypt(source, destination, key=0x0AEEF6)
    file = File.open(source, "rb")
    data = file.read
    file.close
    s = []
    xorval = key
    data.each_byte{|byte|
    r = byte.to_i ^ xorval
    s << r
    xorval = xorval * 2 + 113 & 0xFFFFFFFF
    }
    $data = s
    file = File.open(destination, 'wb')
    Marshal.dump($data, file)
    file.close
  end
  
  #===========================================================
  #**xorify_eval
  #**Evals a xorify encrypted script
  #**Wykonuje skrypt zakodowany algorytmem xorify
  #**Narzew
  #===========================================================
  
  def xorify_eval(packed, key=0x0AEEF6, raiseonfailure=0)
    file = File.open(packed, 'rb')
    $data = Marshal.load(file)
    s = []
    xorval = key
    $data.each{|x|
    r = x ^ xorval
    s << r
    xorval = xorval * 2 + 113 & 0xFFFFFFFF
    }
    a = []
    s.each{|x|
    a << $nrgss.unpack_byte_clear(x)
    }
    script = a.to_s
    begin
      eval(script)
    rescue
      raise("Failed to load script") if raiseonfailure == 1
      print("Failed to load script") if raiseonfailure == 0
    end
  end
  
  #===========================================================
  #**mci_eval
  #**Gets a command from MCI DLL
  #**Wykonuje komendę na bibliotece MCI
  #**ForeverZer0
  #===========================================================
  
  def mci_eval(command)
    data = "\0" * 256
    $mcisendstring.call(command, data, 256, 0)
    return data.delete("\0")
  end
  
  #===========================================================
  #**open_cd_drive
  #**Opens CD drive
  #**Otwiera napęd CD
  #**ForeverZer0
  #===========================================================
  
  def open_cd_drive
    $nrgss.mci_eval('set CDAudio door open')
  end
  
  #===========================================================
  #**close_cd_drive
  #**Closes CD drive
  #**Zamyka napęd CD
  #**ForeverZer0
  #===========================================================
  
  def close_cd_drive
    $nrgss.mci_eval('set CDAudio door closed')
  end
  
  #===========================================================
  #**string_int
  #**Converts string to integer
  #**Konwertuje ciąg na liczbę
  #**Narzew
  #===========================================================
  
  def string_int(string)
    return string.to_i(36)
  end
  
  #===========================================================
  #**int_string
  #**Converts int to string
  #**Konwertuje liczbę na ciąg
  #**Narzew
  #===========================================================
  
  def int_string(int)
    return int.to_s(36)
  end
  
  #===========================================================
  #**tea97_hash
  #**Hashs int using TEA97 hashing algorithm. Ruby 1.8 only
  #**Hashuje liczbę używając algorytmu TEA97. Tylko Ruby 1.8
  #**Narzew
  #===========================================================
  
  def tea97_hash(x,y=133,z=413,k=817)
    $k = k.to_i + 113
    $y = y.to_i + 103
    $z = z.to_i + 404
    $result = []
    x = x.crypt(($k * $z + $y).to_s)
    x.each_byte{|b|
    s = b.to_i
    a = s.to_i ^ y.to_i + 4
    b = a.to_i ^ y.to_i + 7
    c = b ^ y.to_i + $k.to_i
    d = c ^ (y.to_i + 2) * $k.to_i
    e = d ^ (z.to_i + 7) * $k.to_i
    f = e ^ (z.to_i + k.to_i) * 3
    g = f ^ (y.to_i + z.to_i + 330) * 3
    h = g ^ $k.to_i
    $result << (h.to_i ^ k.to_i + 7)
    $k = $k.to_i * 2 + 5 & 0xFFFFFF
    }
    $result = $result.to_s.to_i / ($k * 348 + $y + 329429378 + $z * 117 + $k * 1113244)
    $result = $result.to_s
    return $result
  end
  
  #===========================================================
  #**xt_unpack
  #**Depacks xt packed array
  #**Depakowuje tablicę zapakowaną xt
  #**Narzew
  #===========================================================
  
  def xt_unpack(table, key=0)
    $key = key
    $xt = []
    table.each{|x|
    $xt << ((x - $key).to_s(36))
    $key = $key * 2 + 6
    }
    return $xt
  end
  
  #===========================================================
  #**xt_pack
  #**Packs array using xt algorithm
  #**Pakuje tablicę używając algorytmu xt
  #**Narzew
  #===========================================================
  
  def xt_pack(table, key=0)
    $key = key
    $xt = []
    table.each{|x|
    $xt << (x.to_i(36) + $key)
    $key = $key * 2 + 6
    }
    return $xt
  end
  
  #===========================================================
  #**make_rbl
  #**Makes a rbl from data array
  #**Tworzy rbl z tablicy
  #**Narzew
  #===========================================================
  
  def make_rbl(archivedata, file2)
    $result = {}
    $archive = archivedata
    $archive.each{|x,y|
    $result[$nrgss.uu_encode(x)] = Zlib::Deflate.deflate(y)
    }
    file = File.open(file2, 'wb')
    Marshal.dump($result, file)
    file.close
  end
  
  #===========================================================
  #**execute_rbl
  #**Executes a rbl section
  #**Ładuje sekcję rbl
  #**Narzew
  #===========================================================
  
  def execute_rbl(archivesection, archive, args=[])
    $rbl_args = args
    file = File.open(archive, 'rb')
    $result = Marshal.load(file)
    file.close
    $data = {}
    $result.each{|x,y|
    $data[x] = Zlib::Inflate.inflate(y)
    }
    eval($data[$nrgss.uu_decode(x)])
  end
  
  #===========================================================
  #**eval_all_rbl
  #**Executes all rbl sections. Will crash if it's function-caller library.
  #**Ładuje wszystkie sekcje rbl. Zwróci błąd jeśli to function-caller.
  #**Narzew
  #===========================================================
  
  def eval_all_rbl(rbl)
    file = File.open(rbl, 'rb')
    $result = Marshal.load(file)
    file.close
    $data = {}
    $result.each{|x,y|
    $data[x] = Zlib::Inflate.inflate(y)
    }
    $data.each{|x,y|
    eval(y)
    }
  end
  
  #===========================================================
  #**encrypt_int2
  #**Encrypts an int (Method 2)
  #**Koduje liczbę (Metoda 2)
  #**Narzew
  #===========================================================
  
  def encrypt_int2(int, key)
    $int = int * 17 + 113
    $key = (key + (114 * 19 - 724) * key)
    srand(key) rescue srand(9200)
    $r = $int
    rand(2000).times{
    srand($key + 3)
    $r = $r ^ ($key + 7)
    $r = $r + rand(200 + $key)
    $key = $key + rand(3999)
    }
    return $r
  end
  
  #===========================================================
  #**fgetb
  #**???
  #**???
  #**Peter O.
  #===========================================================
  
  def fgetb
    x=0
    ret=0
    each_byte do |i|
      ret=i || 0
      break
    end
    return ret
  end
  
  #===========================================================
  #**fgetw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def fgetw
    x=0
    ret=0
    each_byte do |i|
      break if !i
      ret|=(i<<x)
      x+=8
      break if x==16
    end
    return ret
  end
  
  #===========================================================
  #**fgetdw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def fgetdw
    x=0
    ret=0
    each_byte do |i|
      break if !i
      ret|=(i<<x)
      x+=8
      break if x==32
    end
    return ret
  end
  
  #===========================================================
  #**fgetsb
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def fgetsb
    ret=fgetb
    if (ret&0x80)!=0
      return ret-256
    else
      return ret
    end
  end
  
  #===========================================================
  #**xfgetb
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def xfgetb(offset)
    self.pos=offset
    return fgetb
  end
  
  #===========================================================
  #**xfgetw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def xfgetw(offset)
    self.pos=offset
    return fgetw
  end
  
  #===========================================================
  #**xfgetdw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def xfgetdw(offset)
    self.pos=offset
    return fgetdw
  end
  
  #===========================================================
  #**getoffset
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def getoffset(index)
    self.nil
    self.pos=0
    offset=fgetdw>>3
    return 0 if index>=offset
    self.pos=index*8
    return fgetdw
  end
  
  #===========================================================
  #**getlength
  #**???
  #**???
  #**PeterO.
  #===========================================================

  def getlength(index)
    self.nil
    self.pos=0
    offset=fgetdw>>3
    return 0 if index>=offset
    self.pos=index*8+4
    return fgetdw
  end

  #===========================================================
  #**readname
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def readname(index)
    self.nil
    self.pos=0
    offset=fgetdw>>3
    return "" if index>=offset
    self.pos=index<<3
    offset=fgetdw
    length=fgetdw
    return "" if length==0
    self.pos=offset
    return read(length)
  end
  
  #===========================================================
  #**fputb
  #**???
  #**???
  #**Peter O.
  #===========================================================
  
  def fputb(b)
    b=b&0xFF
    write(b.chr)
  end
  
  #===========================================================
  #**fputw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def fputw(w)
    2.times do
      b=w&0xFF
      write(b.chr)
      w>>=8
    end
  end
  
  #===========================================================
  #**fputdw
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def fputdw(w)
    4.times do
      b=w&0xFF
      write(b.chr)
      w>>=8
    end
  end
  
  #===========================================================
  #**pos=
  #**???
  #**???
  #**Peter O.
  #===========================================================

  def pos=(value)
    seek(value)
  end
  
  #===========================================================
  #**swap32
  #**Swaps bytes
  #**Zamienia bity
  #**Peter O.
  #===========================================================
  
  def swap32(x)
    return ((x>>24)&0x000000FF)|((x>>8)&0x0000FF00)|((x<<8)&0x00FF0000)|((x<<24)&0xFF000000)
  end
  
  #===========================================================
  #**gcd
  #**The greatest common divisor
  #**Największy wspólny dzielnik
  #**KGC
  #===========================================================
  
  def gcd(x)
    ary = x.find_all { |i| i.is_a?(Integer) && i != 0 }
    ary.sort! { |a, b| b - a }
    return 0 if ary.size < 2
    g = ary[0].abs
    (1...ary.size).each { |i|
      n = ary[i].abs
      g = gcd_r(g, n)
    }
    return g
  end
  
  #===========================================================
  #**gcd_r
  #**???
  #**???
  #**Required function.
  #**KGC
  #===========================================================
  
  def gcd_r(a, b)
    while b != 0
      c = a
      a = b
      b = c % b
    end
    return a
  end
  
  #===========================================================
  #**lcm
  #**The smallest common multiple
  #**Najmniejsza wspólna wielokrotność
  #**KGC
  #===========================================================
  
  def lcm(x)
    ary = x.find_all { |i| i.is_a?(Integer) && i != 0 }
    return 0 if ary.size < 2
    l = ary[0].abs
    (1...ary.size).each { |i|
      n = ary[i].abs
      l = l * n / [l, n].gcd
    }
    return l
  end
  
  #===========================================================
  #**average
  #**The average number from array
  #**Średnia z numerów tablicy
  #**KGC
  #===========================================================
  
  def average(value)
    n = 0.0
    value.each {|i| n += i}
    return n / value.size
  end
  
  #===========================================================
  #**devsq
  #**Sum of squared deviations
  #**Suma kwadratów odchyleń
  #**KGC
  #===========================================================
  
  def devsq(value)
    n, v = 0.0, average(value)
    value.each {|i| n += (i - v) ** 2}
    return n
  end
  
  #===========================================================
  #**gmt
  #**Geometric mean (synergistic)
  #**Średnia geometryczna (synergetsyczna)
  #**KGC
  #===========================================================
  
  def gmt(value)
    n = 1.0
    value.each {|i| n *= i}
    return n ** (1.0 / value.size)
  end
  
  #===========================================================
  #**stdevp
  #**Standard deviation
  #**Odchylenie standardowe
  #**KGC
  #===========================================================
  
  def stdevp(value)
    return sqrt(var(value))
  end
  
  #===========================================================
  #**var
  #**Unbiased variance
  #**Bezstronna wariancja
  #**KGC
  #===========================================================
  
  def var(value)
    return 0.0 if value.size < 2
    return devsq(value) / (value.size - 1)
  end
  
  #===========================================================
  #**Ends of NRGSS class
  #**Koniec klasy NRGSS
  #===========================================================
  
end

#===========================================================
#**NRGSS Class Definition
#**Definicja klas NRGSS
#===========================================================

$nrgss = NRGSS.new

#===========================================================
#**End of Library
#**Koniec biblioteki
#===========================================================
