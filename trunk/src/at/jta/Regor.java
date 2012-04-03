package at.jta;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;


/********************************************************************************************************************************
 *
 * <p>Title: Class is 100% pur Java Registry handle</p>
 *
 * <p>Description:  You can read, delete or create any key in the registry (when you have access rights).
 * But you just can read/write and set string values! The java.dll doesnt provide any other feature.<br>
 * <b>ATTENTION: Since version 3 you can also read/write dword, binary, expand and multi data - but this is implemented by calling
 * the regedit executeable with parameters and temporary files - so it might not success or have a deadlock!!!</b></p>
 *
 * <p>Copyright: Copyright (c) 2009 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 2.0 22.03.2007 Methods are renamed and now called by the function the are implementing and the document is now in
 *              english, instead of german<br><br>
 * @version 3.0 03.06.2008 Replaced all int Key values with Key class for storing the path and added new methods for
 *                         reading/writing dword, binary, multi and expand values (these new methods are tested under XP SP2 and
 *                         Vista Ultimate x64 with admin privliges and UCL turned off, so if there are any bugs with other windows
 *                         version please submit it to me - or just to say thank you or to donate ;-))<br>
 *                         All OLD methods are stil here and the start with _<br>
 * @version 3.1 15.10.2008 extractAnyValue had a bug,when reading out items which goes over more lines (JTA)<br>
 * @version 3.2 17.10.2008 added caching methods for caching many registry entries + values<br>
 * @version 3.3 20.10.2008 found major bug in the method extractAnyValue - the method returned and value found with the name, not only
 *  for the right key<br>
 * @version 3.4 21.10.2008 bug in the parseHexString method when you want to replace the 0 signs! It removed every 0 sign
 * @released 21.10.2008 (internal release)
 * @version 4.0 RC2 14.04.2009 From a discussion at the java-forum.org board, a member told me, that there is also a native
 *                     command called "reg.exe" and vista doesnt need admin privileges when you run it! So the version checks if
 *                     reg.exe is here! If not take regedit.exe
 *                     reg.exe is faster, not so much memory consuming (while parsing cached keys) and under vista UAC is not such
 *                     a big problem as with regedit.exe! The best result is, that you dont need to convert the data anymore
 *                     (if you stil do it, because upgrading from older version, it doesnt matter - so the result will be the same)
 * @version 4.1 preRelease 29.04.2009 Due lack of time (i was climbing at the weekend) i never released the 4.0 RC2, but i decided to built
 *                     some new functions and so I will bring out the verison 4.1 with 2 new methods: getKeyType and readAnyValue
 * @version 4.2 Release 23.02.2010 As i changed my workplace and i forgot to release the new source as jar-file, I finaly release 
 *                      a newer version, which should be Win7/Vista safe, because it uses reg.exe instead of regedit.exe (for non DWORD entries)
 *                      I also switched from my JBuilder2k5 to Eclipse, because my new company didnt want to buy me a Jbuilder :( - at least SVN support is now better :D 
 * @version 4.3 Release 30.04.2010 I checked in a debug version, so that it will not work under vista or win7 without admin privs, because it was not
 *  					looking after reg.exe. I also found some parsing errors and fixed them..  
 * @version 4.4 Release 17.05.2010 After a user told me, he has problems reading out binary entries, i discovered several bugs with vista and win7. It seems to be
 * 						that the output from reg.exe has been changed. I just tested with XP and never with vista/win7, but now i made tests with win7 
 * 						and everything seems to be ok - now ;)
 * @version 4.5 Release 03.04.2012 Issue mentioned by fischl-thomas at 26. January 2012 - on XP, REG_SZ was not working anymore (because of the previous update to Win7)               
 *******************************************************************************************************************************/
final public class Regor
{
	/**
	 * version handle to difference between version - introduced with version 4.5 = 450
	 */
	public static final long serialVersionUID = 450L;	
	
  /**
   * the old handle to the HKEY_CLASSES_ROOT registry root node
   */
  public static final int _HKEY_CLASSES_ROOT = 0x80000000;
  /**
   * the old handle to the HEKY_CURRENT_USER registry root node
   */
  public static final int _HKEY_CURRENT_USER = 0x80000001;
  /**
   * the old handle to the HKEY_LOCAL_MACHINE registry root node
   */
  public static final int _HKEY_LOCAL_MACHINE = 0x80000002;

  /**
   * the NEW handle to the HKEY_CLASSES_ROOT registry root node
   */
  public static final Key HKEY_CLASSES_ROOT = new Key(_HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT");
  /**
   * the NEW handle to the HEKY_CURRENT_USER registry root node
   */
  public static final Key HKEY_CURRENT_USER = new Key(_HKEY_CURRENT_USER, "HKEY_CURRENT_USER");
  /**
   * the NEW handle to the HKEY_LOCAL_MACHINE registry root node
   */
  public static final Key HKEY_LOCAL_MACHINE = new Key(_HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE");

  public static final int ERROR_SUCCESS = 0;
  public static final int ERROR_FILE_NOT_FOUND = 2;
  public static final int ERROR_ACCESS_DENIED = 5;

  /* Constants used to interpret returns of native functions    */
  public static final int NATIVE_HANDLE = 0;
  public static final int ERROR_CODE = 1;
  public static final int SUBKEYS_NUMBER = 0;
  public static final int VALUES_NUMBER = 2;
  public static final int MAX_KEY_LENGTH = 3;
  public static final int MAX_VALUE_NAME_LENGTH = 4;


  /* Windows security masks */
  /**
   * Security Mask need by openKey - just for delete
   */
  public static final int DELETE = 0x10000;
  /**
   * Security Mask need by openKey - just for querying values
   */
  public static final int KEY_QUERY_VALUE = 1;
  /**
   * Security Mask need by openKey - just for setting values
   */
  public static final int KEY_SET_VALUE = 2;
  /**
   * Security Mask need by openKey - for creating sub keys
   */
  public static final int KEY_CREATE_SUB_KEY = 4;
  /**
   * Security Mask need by openKey - for enum sub keys
   */
  public static final int KEY_ENUMERATE_SUB_KEYS = 8;
  /**
   * Security Mask need by openKey - for key reading
   */
  public static final int KEY_READ = 0x20019;
  /**
   * Security Mask need by openKey - for writing keys
   */
  public static final int KEY_WRITE = 0x20006;
  /**
   * Security Mask need by openKey - highest access to do everything (default access by openkey without security mask)
   */
  public static final int KEY_ALL_ACCESS = 0xf003f;

  private Method openKey = null;
  private Method closeKey = null;
  private Method delKey = null;
  private Method createKey = null;
  private Method flushKey = null;
  private Method queryValue = null;
  private Method setValue = null;
  private Method delValue = null;
  private Method queryInfoKey = null;
  private Method enumKey = null;
  private Method enumValue = null;

  /**
   * Needed to replace the entries in exported tmp registry file
   */
  private static final String NULL_STRING = new String(new char[]{0});

  /**
   * Standard text for inserting in the registry - used for import dword, binary, multi and expand
   */
  private static final String INIT_WINDOWS_STRING = "Windows Registry Editor Version 5.00";

  /**
   * Every binary entry starts with this (when exported or for the import)
   */
  private static final String BINARY_KEY_IDENT = "hex:";

  /**
   * Every dword entry starts with this, also used for import
   */
  private static final String DWORD_KEY_IDENT = "dword:";

  /**
   * Every multi string entry starts with this, also used for import
   */
  private static final String MULTI_KEY_IDENT = "hex(7):";

  /**
   * Every expand string entry starts with this, also used for import
   */
  private static final String EXPAND_KEY_IDENT = "hex(2):";

  /**
   * Time (milliseconds) for waiting for a file to grow (needed for caching and reading dword, binary, multi and expand values)
   */
  public static int WAIT_FOR_FILE = 250;


  /**
   * List for cached registry entires
   */
  private ArrayList caches;

  /**
   * If you want to use cached entries. The method readBinary, readDword, readExpand and readMulti just use caches (not readValue)
   */
  private boolean useCache = false;

  /**
   * Handler to reg.exe or regedit.exe to read, save and cache entries
   */
  private INativeRegistryHandler nativeHandler = null;

  /**
   * If the registry entry is a normal string key (plain key) - use <code>getKeyType(Key key, String valueName)/<code> to get the type
   */
  public static final int PLAIN_KEY = 1;

  /**
   * If the registry entry is a binary key - use <code>getKeyType(Key key, String valueName)/<code> to get the type
   */
  public static final int BINARY_KEY = 2;

  /**
   * If the registry entry is a dword key - use <code>getKeyType(Key key, String valueName)/<code> to get the type
   */
  public static final int DWORD_KEY = 3;

  /**
   * If the registry entry is a multi string key - use <code>getKeyType(Key key, String valueName)/<code> to get the type
   */
  public static final int MULTI_KEY = 4;

  /**
   * If the registry entry is a expand string key - use <code>getKeyType(Key key, String valueName)/<code> to get the type
   */
  public static final int EXPAND_KEY = 5;

  /**
   *
   */
  private static final String BINARY_KEY_NAME = "REG_BINARY";

  /**
   *
   */
  private static final String DWORD_KEY_NAME = "REG_DWORD";

  /**
   *
   */
  private static final String MULTI_KEY_NAME = "REG_MULTI_SZ";

  /**
   *
   */
  private static final String EXPAND_KEY_NAME = "REG_EXPAND_SZ";

  /**
   *
   */
  private static final String PLAIN_KEY_NAME = "REG_SZ";


  /******************************************************************************************************************************
   * Constructor to handle with windows registry
   * @throws RegistryErrorException throws an registryerrorException when its not able to get a handle to the registry methods
   * @throws NotSupportedOSException throws an notSupportedOSException if the registry is not used in windows
   *****************************************************************************************************************************/
  public Regor() throws RegistryErrorException
  {
    checkOS();
    initMethods();
    initNatvieRegistry();
  }

  /******************************************************************************************************************************
   * Method checks either if its windows or anohter system (if not windows an exception is thrown) - just needed for internal checks
   *****************************************************************************************************************************/
  private void checkOS()
  {
    String str = System.getProperty("os.name");
    if(str == null || str.toLowerCase().indexOf("windows") == -1)
      throw new NotSupportedOSException("Operating system: " + str + " is not supported!");
  }

  ////// DIRTY METHODS START HERE - THE METHODS DONT USE A DLL TO READ/WRITE ENTRIES, NO THE USE RUNTIME AND THE REGEDIT EXECUTABLE///

  /***********************************************************************************************************************************
   * Method saves a binary entry for the given key, valuename and data
   * @deprecated use <code>savePlainBinary</code> instead of this method
   * @since version 3 (03.06.2008)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key The parent key handle obtained by openKey
   * @param valueName String the binary value name in the registry
   * @param hexCommaData String the string converted in hexadecimal signs separated with commas.
   * Use <code>String convertStringToHexComma(String plainString, false)</code> to get the hex comma separated data
   * @throws RegistryErrorException
   **********************************************************************************************************************************/
  public void saveBinary(Key key, String valueName, String hexCommaData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegHandler)
      System.err.println("ATTENTITION!! WRONG METHOD TO STORE BINARY ENTRIES!! PLEASE USE savePlainBinary!");
    nativeHandler.saveAnyValue(key.getPath(), valueName, BINARY_KEY_IDENT, hexCommaData);
  }

  /**********************************************************************************************************************************
   * Method saves a binary entry for the given key, valuename and data
   * @since version 4 (27.03.2009)
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key The parent key handle obtained by openKey
   * @param valueName String the binary value name in the registry
   * @param plainData String like you would see in the registry (without any spaces, etc..)
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void savePlainBinary(Key key, String valueName, String plainData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegeditHandler)
      plainData = convertStringToHexComma(plainData, false);
    else
      plainData = convertStringToHex(plainData);
    nativeHandler.saveAnyValue(key.getPath(), valueName, BINARY_KEY_IDENT, plainData);
  }

  /**********************************************************************************************************************************
   * Method reads from the registry a BINARY value - this is made via Runtime.getRuntime().exec(regedit) and is not one
   * of the best methods, but at least it doesnt need a dll
   * @since version 3 (03.06.2008 - guess who has birthday ;))
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key the obtained key from the registry
   * @param valueName String the valueName of the binary entry which you want to read
   * @return String null or the binary data separated by comma
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public String readBinary(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null)
      throw new NullPointerException("Valuename cannot be null, because the default value is always a STRING! If you want to read a String use readValue");
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    String ret = nativeHandler.extractAnyValue(key.getPath(), valueName, false);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(BINARY_KEY_IDENT))
      return ret.substring(4);
    //if the reghandler or caching is active, the plain key will be returned
    else if(ret != null && ( nativeHandler instanceof RegHandler || isCachingActive()))
      return ret;
    return null;
  }

  /**********************************************************************************************************************************
   * Method saves a dword entry in the registry
   * @since version 3 (03.06.2008)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the valuename of the dword entry
   * @param hexData String a hexadecimal String withouth comma or spaces (use <code>Long.toHexString(long)</code> to get a hex string)
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void saveDword(Key key, String valueName, String hexData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    try{
      if(Long.parseLong(hexData, 16) > 4294967295L)
        throw new RegistryErrorException("Dword entry to high for registry! FFFF FFFF is the highest value!");
    }
    catch(Exception ex){
      throw RegistryErrorException.getException(ex);
    }
    nativeHandler.saveAnyValue(key.getPath(), valueName, DWORD_KEY_IDENT, hexData);
  }

  /**********************************************************************************************************************************
   * Method reads the dword entry from the registry
   * @since version 3 (03.06.2008 - dont know who has birthday?)
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the dword value
   * @return String the dword entry in a hex string
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public String readDword(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null)
      throw new NullPointerException("Valuename cannot be null, because the default value is always a STRING! If you want to read a String use readValue");
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    String ret = nativeHandler.extractAnyValue(key.getPath(), valueName, false);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(DWORD_KEY_IDENT))
      return ret.substring(6);
    //if the reghandler or caching is active, the plain key will be returned
    else if(ret != null && ( nativeHandler instanceof RegHandler || isCachingActive()))
      return ret;
    return null;
  }

  /***********************************************************************************************************************************
   * Method saves a multi string entry in the registry
   * @deprecated use <code>savePlainMulti</code> instead of
   * @since version 3 (03.06.2008)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the multi value name
   * @param hexCommaZeroData String the data to write converted in hex string separated by a comma with trailing zeros
   * Use <code>String convertStringToHexComma(String plainString, true)</code> to get the hex comma separated data with 0 signs between
   * @throws RegistryErrorException
   **********************************************************************************************************************************/
  public void saveMulti(Key key, String valueName, String hexCommaZeroData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegHandler)
      System.err.println("ATTENTITION!! WRONG METHOD TO STORE MULTI ENTRIES!! PLEASE USE savePlainMulti!");
    nativeHandler.saveAnyValue(key.getPath(), valueName, MULTI_KEY_IDENT, hexCommaZeroData);
  }

  /**********************************************************************************************************************************
   * Method saves a multi string entry in the registry
   * @since version 4 (27.03.2009)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the multi value name
   * @param plainData String
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void savePlainMulti(Key key, String valueName, String plainData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegeditHandler)
      plainData = convertStringToHexComma(plainData, true);
    nativeHandler.saveAnyValue(key.getPath(), valueName, MULTI_KEY_IDENT, plainData);
  }

  /**********************************************************************************************************************************
   * Method reads a multi string entry from the registry
   * @since version 3 (03.06.2008 - my dad has birthday ;))
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the multi value name
   * @return String the HEXADECIMAL values separated by comma (use <code>String parseHexString(String)</code> to convert it
   * the line seperator is also a hex null! You have to parse it out
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public String readMulti(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null)
      throw new NullPointerException("Valuename cannot be null, because the default value is always a STRING! If you want to read a String use readValue");
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    String ret = nativeHandler.extractAnyValue(key.getPath(), valueName, false);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(MULTI_KEY_IDENT))
      return ret.substring(7);
    //if the reghandler or caching is active, the plain key will be returned
    else if(ret != null && ( nativeHandler instanceof RegHandler || isCachingActive()))
      return ret;
    return null;
  }

  /**********************************************************************************************************************************
   * Method saves an expand string entry
   * @deprecated use <code>savePlainExpand</code> instead of
   * @since version 3 (03.06.2008)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the expand value name
   * @param hexCommaZeroData String the data to write converted in hex string separated by a comma with trailing zeros
   * Use <code>String convertStringToHexComma(String plainString, true)</code> to get the hex comma separated data with 0 signs between
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void saveExpand(Key key, String valueName, String hexCommaZeroData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegHandler)
      System.err.println("ATTENTITION!! WRONG METHOD TO STORE EXPAND ENTRIES!! PLEASE USE savePlainExpand!");
    nativeHandler.saveAnyValue(key.getPath(), valueName, EXPAND_KEY_IDENT, hexCommaZeroData);
  }

  /**********************************************************************************************************************************
   * Method saves an expand string entry
   * @since version 4 (27.03.2009)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the expand value name
   * @param plainData String
   * @throws RegistryErrorException
   **********************************************************************************************************************************/
  public void savePlainExpand(Key key, String valueName, String plainData) throws RegistryErrorException
  {
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    if(nativeHandler instanceof RegeditHandler)
      plainData = convertStringToHexComma(plainData, true);
    nativeHandler.saveAnyValue(key.getPath(), valueName, EXPAND_KEY_IDENT, plainData);
  }

  /**********************************************************************************************************************************
   * Method reads an expand string entry
   * @since version 3 (03.06.2008)
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the expand value name
   * @return String the HEXADECIMAL values separated by comma (use <code>String parseHexString(String)</code> to convert it
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public String readExpand(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null)
      throw new NullPointerException("Valuename cannot be null, because the default value is always a STRING! If you want to read a String use readValue");
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    String ret = nativeHandler.extractAnyValue(key.getPath(), valueName, false);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(EXPAND_KEY_IDENT))
      return ret.substring(7);
    //if the reghandler or caching is active, the plain key will be returned
    else if(ret != null && ( nativeHandler instanceof RegHandler || isCachingActive()))
      return ret;
    return null;
  }

  ////// DIRTY METHODS STOP HERE - THE METHODS DONT USE A DLL TO READ/WRITE ENTRIES, NO THE USE RUNTIME AND THE REGEDIT EXECUTABLE///

  /******************************************************************************************************************************
   * Reading every valueName (not only the string value) out of the registry handle (for maximum value index and maxValueNameLength
   * use the getChildInformation method
   * @param key the handle to the parent key obtained from openKey
   * @param valueNameIndex the index of the valueName name - starting from 0 going to the maximum count from the getChildInformation
   * stored in array index 2
   * @param maxValueNameLength maximum length of valueName name (used because for memory allocating in the java.dll - if you obtain
   * the size from getChildInformation increase the [4] int array by 1)
   * @return byte[] either the name of the valueName or null if not found or an error occurs or if the maxValueNameLength is to short
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public byte[] enumValueName(Key key, int valueNameIndex, int maxValueNameLength) throws RegistryErrorException
  {
    return _enumValueName(key.getKey(), valueNameIndex, maxValueNameLength);
  }

  /******************************************************************************************************************************
   * Reading every valueName (not only the string value) out of the registry handle (for maximum value index and maxValueNameLength
   * use the getChildInformation method
   * @param key the handle to the parent key obtained from openKey
   * @param valueNameIndex the index of the valueName name - starting from 0 going to the maximum count from the getChildInformation
   * stored in array index 2
   * @param maxValueNameLength maximum length of valueName name (used because for memory allocating in the java.dll - if you obtain
   * the size from getChildInformation increase the [4] int array by 1)
   * @return byte[] either the name of the valueName or null if not found or an error occurs or if the maxValueNameLength is to short
   * @throws RegistryErrorException
   * @deprecated use <code>byte[] enumValueName(Key key, int valueNameIndex, int maxValueNameLength)</code> instead of
   *****************************************************************************************************************************/
  public byte[] _enumValueName(int key, int valueNameIndex, int maxValueNameLength) throws RegistryErrorException
  {
    try
    {
      return (byte[])enumValue.invoke(null, new Object[] {new Integer(key), new Integer(valueNameIndex), new Integer(maxValueNameLength)});
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /*****************************************************************************************************************************
   * Returns every valueName (not only the String value names)
   * @param key either one of the root nodes or a key obtained from openKey
   * @param subkey a string to a subkey - if  the subkey is empty or null the information will be obtained from the given key
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   ****************************************************************************************************************************/
  public List listValueNames(Key key, String subkey) throws RegistryErrorException
  {
    return _listValueNames(key.getKey(), subkey);
  }

  /*****************************************************************************************************************************
   * Returns every valueName (not only the String value names)
   * @param key either one of the root nodes or a key obtained from openKey
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   ****************************************************************************************************************************/
  public List listValueNames(Key key) throws RegistryErrorException
  {
    return listValueNames(key,null);
  }

  /*****************************************************************************************************************************
   * Returns every valueName (not only the String value names)
   * @param key either one of the root nodes or a key obtained from openKey
   * @param subkey a string to a subkey - if  the subkey is empty or null the information will be obtained from the given key
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>List listValueNames(Key key, String subkey)</code> instead of
   ****************************************************************************************************************************/
  public List _listValueNames(int key, String subkey) throws RegistryErrorException
  {
    int handle = -1;
    try{
      handle = _openKey(key, subkey, KEY_READ); //just reading priv
      if(handle != -1)
      {
        int info[] = _getChildInformation(handle); //obtain the informations
        if(info != null && info[0] != -1)
        {
          List ret = new ArrayList();
          for(int x = 0; x != info[2]; x++)
          {
            String tmp = parseValue(_enumValueName(handle,x,info[4] + 1));
            if(tmp != null) //just if not null, maybe there are no valueNames
              ret.add(tmp);
          }
          return ret.isEmpty() ? null : ret;
        }
      }
    }
    catch(RegistryErrorException ex)
    {
      throw ex;
    }
    catch(Exception ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    finally{
      _closeKey(handle);
    }
    return null;
  }

  /*****************************************************************************************************************************
   * Returns every valueName (not only the String value names)
   * @param key either one of the root nodes or a key obtained from openKey
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>List listValueNames(Key key)</code> instead of
   ****************************************************************************************************************************/
  public List _listValueNames(int key) throws RegistryErrorException
  {
    return _listValueNames(key,null);
  }

  /******************************************************************************************************************************
   * Reading the subkey name out of the registry (to obtain the count and the maxKeyNameLength use <code>getChildInformation</code>
   * method
   * @param key the handle to the key obtained by openKey
   * @param subkeyIndex index from the subkey from which you want to obtain the name (start with 0 - the maximum count you get from
   * getChildInformation method in array [0])
   * @param maxKeyNameLength the maximum length of a subkey name (used because for memory allocating in the java.dll - if you obtain
   * the size from getChildInformation increase the [3] int array by 1 )
   * @return byte[] on error or not found or the maxKeyNameLength is to short it will returns null, on success the name of the subkey
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public byte[] enumKeys(Key key, int subkeyIndex, int maxKeyNameLength) throws RegistryErrorException
  {
    return _enumKeys(key.getKey(), subkeyIndex, maxKeyNameLength);
  }

  /******************************************************************************************************************************
   * Reading the subkey name out of the registry (to obtain the count and the maxKeyNameLength use <code>getChildInformation</code>
   * method
   * @param key the handle to the key obtained by openKey
   * @param subkeyIndex index from the subkey from which you want to obtain the name (start with 0 - the maximum count you get from
   * getChildInformation method in array [0])
   * @param maxKeyNameLength the maximum length of a subkey name (used because for memory allocating in the java.dll - if you obtain
   * the size from getChildInformation increase the [3] int array by 1 )
   * @return byte[] on error or not found or the maxKeyNameLength is to short it will returns null, on success the name of the subkey
   * @throws RegistryErrorException
   * @deprecated use <code>byte[] enumKeys(Key key, int subkexindex, int maxKeyNameLength)</code> instead of
   *****************************************************************************************************************************/
  public byte[] _enumKeys(int key, int subkeyIndex, int maxKeyNameLength) throws RegistryErrorException
  {
    try
    {
      return (byte[])enumKey.invoke(null, new Object[] {new Integer(key), new Integer(subkeyIndex), new Integer(maxKeyNameLength)});
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Returns all subkeys from the given key and subkey
   * @param key either one of the root nodes or a key obtained from openKey
   * @param subkey a string to a subkey - if  the subkey is empty or null the information will be obtained from the given key
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public List listKeys(Key key, String subkey) throws RegistryErrorException
  {
    return _listKeys(key.getKey(), subkey);
  }

  /*****************************************************************************************************************************
   * Returns all subkeys from the given key
   * @param key either one of the root nodes or a key obtained from openKey
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   ****************************************************************************************************************************/
  public List listKeys(Key key) throws RegistryErrorException
  {
    return listKeys(key, null);
  }

  /******************************************************************************************************************************
   * Returns all subkeys from the given key and subkey
   * @param key either one of the root nodes or a key obtained from openKey
   * @param subkey a string to a subkey - if  the subkey is empty or null the information will be obtained from the given key
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>List listKeys(Key key, String subkey)</code> instead of
   *****************************************************************************************************************************/
  public List _listKeys(int key, String subkey) throws RegistryErrorException
  {
    int handle = -1;
    try{
      handle = _openKey(key, subkey, KEY_READ); //just reading priv
      if(handle != -1)
      {
        int info[] = _getChildInformation(handle); //obtain the informations
        if(info != null && info[0] != -1)
        {
          List ret = new ArrayList();
          for(int x = 0; x != info[0]; x++)
          {
            String tmp = parseValue(_enumKeys(handle,x,info[3] + 1));
            if(tmp != null) //just if not null, maybe there are no valueNames
              ret.add(tmp);
          }
          return ret.isEmpty() ? null : ret;
        }
      }
    }
    catch(RegistryErrorException ex)
    {
      throw ex;
    }
    catch(Exception ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    finally{
      _closeKey(handle);
    }
    return null;
  }

  /*****************************************************************************************************************************
   * Returns all subkeys from the given key
   * @param key either one of the root nodes or a key obtained from openKey
   * @return List on success and found a filled list with strings will be returned - on error or nothing found null will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>List listKeys(Key key)</code> instead of
   ****************************************************************************************************************************/
  public List _listKeys(int key) throws RegistryErrorException
  {
    return _listKeys(key,null);
  }

  /******************************************************************************************************************************
   * Reads information about the current opened key (use it when you want to enumKey or enumValueName to determine the maximum
   * key length and the count of keys)
   * @param key the key which you obtained from openKey
   * @return int[0] the count of the subkeys,[2] count of valuenames,
   * [3] the maximum length of a subkey! the maximum length of valuename is stored in[4]
   * (for other operations you should increase the [3] or [4] value by 1 because of the terminating \0 in C - because you handle
   * with the java.dll)
   * if nothing found or illegal key, the values are -1 of the array (at index 1 the value would be 6 the other -1)
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int[] getChildInformation(Key key) throws RegistryErrorException
  {
    return _getChildInformation(key.getKey());
  }

  /******************************************************************************************************************************
   * Reads information about the current opened key (use it when you want to enumKey or enumValueName to determine the maximum
   * key length and the count of keys)
   * @param key the key which you obtained from openKey
   * @return int[0] the count of the subkeys,[2] count of valuenames,
   * [3] the maximum length of a subkey! the maximum length of valuename is stored in[4]
   * (for other operations you should increase the [3] or [4] value by 1 because of the terminating \0 in C - because you handle
   * with the java.dll)
   * if nothing found or illegal key, the values are -1 of the array (at index 1 the value would be 6 the other -1)
   * @throws RegistryErrorException
   * @deprecated use <code>int[] getChildInformation(Key key)</code> instead of
   *****************************************************************************************************************************/
  public int[] _getChildInformation(int key) throws RegistryErrorException
  {
    try
    {
      return (int[])queryInfoKey.invoke(null, new Object[] {new Integer(key)});
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Method deletes the specified value (YOU CAN ALSO DELETE BINARY, DWORD, MULTI OR EXPAND ENTRIES!!!)
   * @since version 4: 14.04.2009
   * @param key the key obtained by openKey
   * @param valueName name of String value you want to delete (if the string is empty or null the default entry will be
   * cleared)
   * @return int
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int deleteEntry(Key key, String valueName) throws RegistryErrorException
  {
    return _delValue(key.getKey(), valueName);
  }

  /******************************************************************************************************************************
   * Method deletes the specified value (YOU CAN ALSO DELETE BINARY, DWORD, MULTI OR EXPAND ENTRIES!!!)
   * @deprecated use <code>int deleteEntry(Key key, String valueName)</code> instead of
   * @param key the key obtained by openKey
   * @param valueName name of String value you want to delete (if the string is empty or null the default entry will be
   * deleted)
   * @return int
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int delValue(Key key, String valueName) throws RegistryErrorException
  {
    return _delValue(key.getKey(), valueName);
  }

  /******************************************************************************************************************************
   * Method deletes the specified value (YOU CAN ALSO DELETE BINARY, DWORD, MULTI OR EXPAND ENTRIES!!!)
   * @param key the key obtained by openKey
   * @param valueName name of String value you want to delete (if the string is empty or null the default entry will be
   * cleared)
   * @return int
   * @throws RegistryErrorException
   * @deprecated use <code>int delValue(Key key, String valueName)</code> instead of
   *****************************************************************************************************************************/
  public int _delValue(int key, String valueName) throws RegistryErrorException
  {
    try
    {
      Integer ret = (Integer)delValue.invoke(null, new Object[] {new Integer(key), getString(valueName)});
      if(ret != null)
        return ret.intValue();
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Method saves the specified string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * Method saves or create a simple character sequence (REG_SZ)
   * If you want to change the default Value the valueName has to be null or nothing
   * @since version 4: 14.04.2009
   * @param key obtained by openKey
   * @param valueName the string value name in the registry you want to set
   * @param value the new value you want to set
   * @return on success, return is ERROR_SUCCESS if not -1 or sth else will be returned
   * @throws RegistryErrorException
   ****************************************************************************************************************************/
  public int saveValue(Key key, String valueName, String value) throws RegistryErrorException
  {
    return _setValue(key.getKey(), valueName, value);
  }

  /******************************************************************************************************************************
   * Method set the specified string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * Methode setzt (oder erstellt) einen Wert auf eine Zeichenfolge
   * Will man den defaulteintrag ändern, so muss man valueName "" übergeben
   * @deprecated use <code>saveValue</code> instead of - just changed name
   * @param key obtained by openKey
   * @param valueName the string value name in the registry you want to set
   * @param value the new value you want to set
   * @return on success, return is ERROR_SUCCESS if not -1 or sth else will be returned
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int setValue(Key key,String valueName, String value) throws RegistryErrorException
  {
    return _setValue(key.getKey(), valueName, value);
  }

  /******************************************************************************************************************************
   * Method set the specified string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * Methode setzt (oder erstellt) einen Wert auf eine Zeichenfolge
   * Will man den defaulteintrag ändern, so muss man valueName "" übergeben
   * @param key obtained by openKey
   * @param valueName the string value name in the registry you want to set
   * @param value the new value you want to set
   * @return on success, return is ERROR_SUCCESS if not -1 or sth else will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>int setValue(Key key, String valueName, String value)</code> instead of
   *****************************************************************************************************************************/
  public int _setValue(int key,String valueName, String value) throws RegistryErrorException
  {
    try
    {
      Integer ret = (Integer)setValue.invoke(null, new Object[] {new Integer(key), getString(valueName), getString(value)});
      if(ret != null)
        return ret.intValue();
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Reads the value of a string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * @param key obtained from openKey
   * @param valueName the string value which you want to read (if you want to obtain the default entry the valueName should be
   * empty or NULL)
   * @return byte[] if found the data in the string value will be returned (to get a string use the class method parseValue(byte[]))
   * on error NULL will be returned
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public String readValueAsString(Key key, String valueName) throws RegistryErrorException
  {
    byte buf[] = readValue(key, valueName);
    if(buf == null)
      return null;
    return parseValue(buf);
  }

  /******************************************************************************************************************************
   * Reads the value of a string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * @param key obtained from openKey
   * @param valueName the string value which you want to read (if you want to obtain the default entry the valueName should be
   * empty or NULL)
   * @return byte[] if found the data in the string value will be returned (to get a string use the class method parseValue(byte[]))
   * on error NULL will be returned
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public byte[] readValue(Key key, String valueName) throws RegistryErrorException
  {
    return _readValue(key.getKey(), valueName);
  }

  /******************************************************************************************************************************
   * Reads the value of a string value (DO NOT USE THIS METHOD FOR READING BINARY, DWORD, MULTI OR EXPAND ENTRIES - JUST
   * FOR SZ - STRING ENTRIES!!!)
   * @param key obtained from openKey
   * @param valueName the string value which you want to read (if you want to obtain the default entry the valueName should be
   * empty or NULL)
   * @return byte[] if found the data in the string value will be returned (to get a string use the class method parseValue(byte[]))
   * on error NULL will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>byte[] readValue(Key key, String valueName)</code> instead of
   *****************************************************************************************************************************/
  public byte[] _readValue(int key, String valueName) throws RegistryErrorException
  {
    try
    {
      byte ret[] = (byte[])queryValue.invoke(null, new Object[] {new Integer(key), getString(valueName)});
      return ret;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Method reads any value and give it back as a string result - this method can be time consuming, since it determines
   * @param key Key
   * @param valueName String
   * @return String
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public String readAnyValueString(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null || valueName.equals(""))
      return readValueAsString(key, valueName);
    try{
      String tmpDataType = nativeHandler.extractAnyValue(key.getPath(), valueName, true);
      if(nativeHandler instanceof RegHandler)
      {
        if(tmpDataType != null && tmpDataType.trim().length() > 0)
        {
        	tmpDataType = tmpDataType.trim();
          if(tmpDataType.startsWith(BINARY_KEY_NAME))
            return tmpDataType.substring(BINARY_KEY_NAME.length() + 1);
          else if(tmpDataType.startsWith(DWORD_KEY_NAME))
            return tmpDataType.substring(DWORD_KEY_NAME.length() + 1);
          else if(tmpDataType.startsWith(PLAIN_KEY_NAME))
            return tmpDataType.substring(PLAIN_KEY_NAME.length() + 1);
          else if(tmpDataType.startsWith(EXPAND_KEY_NAME))
            return tmpDataType.substring(EXPAND_KEY_NAME.length() + 1);
          else if(tmpDataType.startsWith(MULTI_KEY_NAME))
            return tmpDataType.substring(MULTI_KEY_NAME.length() + 1);
        }
      }
      else
      {
        if(tmpDataType != null && tmpDataType.trim().length() > 0)
        {
        	tmpDataType = tmpDataType.trim();
          if(tmpDataType.startsWith(BINARY_KEY_IDENT))
            return parseHexString(tmpDataType.substring(BINARY_KEY_IDENT.length()), false);
          else if(tmpDataType.startsWith(DWORD_KEY_IDENT))
            return tmpDataType.substring(DWORD_KEY_IDENT.length());
          else if(tmpDataType.startsWith(EXPAND_KEY_IDENT))
            return parseHexString(tmpDataType.substring(EXPAND_KEY_IDENT.length()), true);
          else if(tmpDataType.startsWith(MULTI_KEY_IDENT))
            return parseHexString(tmpDataType.substring(MULTI_KEY_IDENT.length()), true);
          else //if it starts with plain text, it should be a plain text field and we remove the trailing and leading "
            return tmpDataType.substring(1, tmpDataType.length() - 2);
        }
      }
    }
    catch(Exception ex)
    {
      throw RegistryErrorException.getException(ex);
    }
//    readValue(key, valueName);
    return null;
  }

  /******************************************************************************************************************************
   * Method returns the type of the key + valuename
   * @param key Key the key handle
   * @param valueName String when valueName is empty or null plain key will be returned, because only plain keys can have empty
   * names
   * @return int 0 = invalid key or cannot determine keytype, 1 = plain, 2 = binary, 3 = dword, 4 = multi, 5 = expand key - use the
   * definied types *_KEY
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int getKeyType(Key key, String valueName) throws RegistryErrorException
  {
    int ret = 0;
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null || valueName.equals(""))
    {
      ret = PLAIN_KEY;
    }
    else
    {
      try{
        String tmpDataType = nativeHandler.extractAnyValue(key.getPath(), valueName, true);
        if(nativeHandler instanceof RegHandler)
        {
          if(tmpDataType != null && tmpDataType.trim().length() > 0)
          {
            if(tmpDataType.startsWith(BINARY_KEY_NAME))
              return BINARY_KEY;
            else if(tmpDataType.startsWith(DWORD_KEY_NAME))
              return DWORD_KEY;
            else if(tmpDataType.startsWith(PLAIN_KEY_NAME))
              return PLAIN_KEY;
            else if(tmpDataType.startsWith(EXPAND_KEY_NAME))
              return EXPAND_KEY;
            else if(tmpDataType.startsWith(MULTI_KEY_NAME))
              return MULTI_KEY;
          }
        }
        else
        {
          if(tmpDataType != null && tmpDataType.trim().length() > 0)
          {
            if(tmpDataType.startsWith(BINARY_KEY_IDENT))
              return BINARY_KEY;
            else if(tmpDataType.startsWith(DWORD_KEY_IDENT))
              return DWORD_KEY;
            else if(tmpDataType.startsWith(EXPAND_KEY_IDENT))
              return EXPAND_KEY;
            else if(tmpDataType.startsWith(MULTI_KEY_IDENT))
              return MULTI_KEY;
            else //if it starts with plain text, it should be a plain text field
              return PLAIN_KEY;
          }
        }
      }
      catch(Exception ex)
      {
        throw RegistryErrorException.getException(ex);
      }
    }
    return ret;
  }

  /******************************************************************************************************************************
   * Flush method - dont know what the method exactly does just implemented because i found it in the java sun source
   * @param key obtained the key from openKey
   * @return on success, ERROR_SUCESS will be returned! on error -1 or sth else
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public int flushKey(Key key) throws RegistryErrorException
  {
    return _flushKey(key.getKey());
  }

  /******************************************************************************************************************************
   * Flush method - dont know what the method exactly does just implemented because i found it in the java sun source
   * @param key obtained the key from openKey
   * @return on success, ERROR_SUCESS will be returned! on error -1 or sth else
   * @throws RegistryErrorException
   * @deprecated use <code>int flushKey(Key key)</code> instead of
   *****************************************************************************************************************************/
  public int _flushKey(int key) throws RegistryErrorException
  {
    try
    {
      Integer ret = (Integer)flushKey.invoke(null, new Object[] {new Integer(key)});
      if(ret != null)
        return ret.intValue();
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * deletes a key/subkey from the registry
   * @param key the parent key obtained by openKey
   * @param subkey the key name you want to delete
   * @return int ERROR_SUCCESS wenn erfolgreich
   * @throws RegistryErrorException if subkey is empty or null or any other exception occurs
   *****************************************************************************************************************************/
  public int delKey(Key key, String subkey) throws RegistryErrorException
  {
    return _delKey(key.getKey(), subkey);
  }

  /******************************************************************************************************************************
   * deletes a key/subkey from the registry
   * @param key the parent key obtained by openKey
   * @param subkey the key name you want to delete
   * @return int ERROR_SUCCESS wenn erfolgreich
   * @throws RegistryErrorException if subkey is empty or null or any other exception occurs
   * @deprecated use <code>int delKey(Key key, String subkey)</code> instead of
   *****************************************************************************************************************************/
  public int _delKey(int key, String subkey) throws RegistryErrorException
  {
    if(subkey == null || subkey.length() == 0)
      throw new RegistryErrorException("subkey cannot be null");
    try
    {
      Integer ret = (Integer)delKey.invoke(null, new Object[] {new Integer(key), getString(subkey)});
      if(ret != null)
        return ret.intValue();
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Create new key/subkey in the registry with the specified name
   * Attentition: if the key is successfully returned, you should close and open the key again, because the obtained key
   * doesnt have a high access level (so maybe creating or deleting a key/value wouldn´t be successful)
   * @param key handle to parent key obtained from openKey
   * @param subkey name of the key/subkey you want to create
   * @return on success the handle to the new key will be returned, otherwhise it will be null
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public Key createKey(Key key, String subkey) throws RegistryErrorException
  {
    int tmpKey = _createKey(key.getKey(), subkey);
    if(tmpKey == -1)
      return null;
    else
      return new Key(key, tmpKey, subkey);
  }

  /******************************************************************************************************************************
   * Create new key/subkey in the registry with the specified name
   * Attentition: if the key is successfully returned, you should close and open the key again, because the obtained key
   * doesnt have a high access level (so maybe creating or deleting a key/value wouldn´t be successful)
   * @param key handle to parent key obtained from openKey
   * @param subkey name of the key/subkey you want to create
   * @return on success the handle to the new key will be returned, otherwhise it will be -1
   * @throws RegistryErrorException
   * @deprecated use <code>Key createKey(Key key, String subkey)</code> instead of
   *****************************************************************************************************************************/
  public int _createKey(int key, String subkey) throws RegistryErrorException
  {
    try
    {
      int result[] = (int[])createKey.invoke(null, new Object[] {new Integer(key), getString(subkey)});
      if(result[ERROR_CODE] == ERROR_SUCCESS)
        return result[NATIVE_HANDLE];
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /*****************************************************************************************************************************
   * Close an obtained key for right usage
   * @param key the key handle
   * @return int on error it will be -1
   * @throws RegistryErrorException
   ****************************************************************************************************************************/
  public int closeKey(Key key) throws RegistryErrorException
  {
    return _closeKey(key.getKey());
  }

  /*****************************************************************************************************************************
   * Close an obtained key for right usage
   * @param key the key handle
   * @return int on error it will be -1
   * @throws RegistryErrorException
   * @deprecated use <code>closeKey(Key key)</code> instead of
   ****************************************************************************************************************************/
  public int _closeKey(int key) throws RegistryErrorException
  {
    try
    {
      Integer ret = (Integer)closeKey.invoke(null, new Object[] {new Integer(key)});
      if(ret != null)
        return ret.intValue();
      else
        return -1;
    }
    catch (InvocationTargetException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalArgumentException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
    catch (IllegalAccessException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /******************************************************************************************************************************
   * Opens a registry key
   * @param key one of the registry root nodes - either HKEY_CLASSES_ROOT, HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
   * @param subkey the name of the key/subkey like SOFTWARE or HARDWARE - for subkeys use the \\ as delimiter f.e. : SOFTWARE\\MICROSOFT
   * if subkey name is "" or null it returns the handle to the root node
   * @param security_mask the security mask to handle with the opened key (see security mask doc at the begin for detailed information)
   * @return Key on NULL (when not found or not allowed) otherwhise the handle to the obtained key (in the Key Object)
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public Key openKey(Key key, String subkey, int security_mask) throws RegistryErrorException
  {
    int tmpKey = _openKey(key.getKey(), subkey, security_mask);
    if(tmpKey == -1)
      return null;
    else
      return new Key(key, tmpKey, subkey);
  }

  /******************************************************************************************************************************
   * Opens a registry key
   * @param key one of the registry root nodes - either HKEY_CLASSES_ROOT, HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
   * @param subkey the name of the key/subkey like SOFTWARE or HARDWARE - for subkeys use the \\ as delimiter f.e. : SOFTWARE\\MICROSOFT
   * if subkey name is "" or null it returns the handle to the root node
   * @return Key null if not found or not allowed (attention here this methods allways uses the KEY_ALL_ACCESS security mask)
   * on success the handle to key will be returned
   * @throws RegistryErrorException
   *****************************************************************************************************************************/
  public Key openKey(Key key, String subkey) throws RegistryErrorException
  {
    return openKey(key,subkey,KEY_ALL_ACCESS);
  }

  /******************************************************************************************************************************
   * Opens a registry key
   * @param key one of the registry root nodes - either HKEY_CLASSES_ROOT, HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
   * @param subkey the name of the key/subkey like SOFTWARE or HARDWARE - for subkeys use the \\ as delimiter f.e. : SOFTWARE\\MICROSOFT
   * if subkey name is "" or null it returns the handle to the root node
   * @param security_mask the security mask to handle with the opened key (see security mask doc at the begin for detailed information)
   * @return int on error -1 (when not found or not allowed) otherwhise the handle to the obtained key
   * @throws RegistryErrorException
   * @deprecated use <code>openKey(Key key, String subkey, int security_mask)</code> instead of
   *****************************************************************************************************************************/
  public int _openKey(int key, String subkey, int security_mask) throws RegistryErrorException
  {
    try
    {
      int[] result = (int[])openKey.invoke(null, new Object[]{new Integer(key),getString(subkey),new Integer(security_mask)});
      if(result == null || result[ERROR_CODE] != ERROR_SUCCESS)
        return -1;
      else
        return result[NATIVE_HANDLE];
    }
    catch (InvocationTargetException ex1)
    {
      throw RegistryErrorException.getException(ex1);
    }
    catch (IllegalArgumentException ex1)
    {
      throw RegistryErrorException.getException(ex1);
    }
    catch (IllegalAccessException ex1)
    {
      throw RegistryErrorException.getException(ex1);
    }
  }

  /******************************************************************************************************************************
   * Opens a registry key
   * @param key one of the registry root nodes - either HKEY_CLASSES_ROOT, HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
   * @param subkey the name of the key/subkey like SOFTWARE or HARDWARE - for subkeys use the \\ as delimiter f.e. : SOFTWARE\\MICROSOFT
   * if subkey name is "" or null it returns the handle to the root node
   * @return int -1 if not found or not allowed (attention here this methods allways uses the KEY_ALL_ACCESS security mask)
   * on success the handle to key will be returned
   * @throws RegistryErrorException
   * @deprecated use <code>openKey(Key key, String subkey)</code> instead of
   *****************************************************************************************************************************/
  public int _openKey(int key, String subkey) throws RegistryErrorException
  {
    return _openKey(key,subkey,KEY_ALL_ACCESS);
  }

  /******************************************************************************************************************************
   * Intern method which adds the trailing \0 for the handle with java.dll
   * @param str String
   * @return byte[]
   *****************************************************************************************************************************/
  private byte[] getString(String str)
  {
    if(str == null)
      str = "";
    return (str += "\0").getBytes();
  }

  /******************************************************************************************************************************
   * Method removes the trailing \0 which is returned from the java.dll (just if the last sign is a \0)
   * @param buf the byte[] buffer which every read method returns
   * @return String a parsed string without the trailing \0
   *****************************************************************************************************************************/
  public static String parseValue(byte buf[])
  {
    if(buf == null)
      return null;
    String ret = new String(buf);
    if(ret.charAt(ret.length() - 1) == '\0')
      return ret.substring(0,ret.length() - 1);
    return ret;
  }

  /**********************************************************************************************************************************
   * Method converts a hex given String (separated by comma) into a string
   * For Multi entries, every entry ends with HEX 0 so you can split the lines
   * @param hexCommaString String
   * @param deleteNullSigns boolean if you want to remove every 0 sign (delete null signs is needed for multi and expand entries,
   * but not for binary
   * @return String
   *********************************************************************************************************************************/
  public static String parseHexString(String hexCommaString, boolean deleteNullSigns)
  {
    if(hexCommaString == null || hexCommaString.trim().length() == 0)
      return hexCommaString;
    String items[] = hexCommaString.split(",");
    StringBuffer strRet = new StringBuffer();
    //if no comma was found, return the given string
    if(items == null || items.length == 0)
    {
      return hexCommaString;
    }
    else if(items.length == 1)
    {
      //if no space in it, then it is maybe hex string without comma´s
      if (hexCommaString.indexOf(" ") == -1)
      {
        try{
          for(int x = 0; x < hexCommaString.length(); x+=2)
          {
            strRet.append((char)Integer.parseInt(hexCommaString.substring(x, x + 2), 16));
          }
          return strRet.toString();
        }
        catch(Exception ex) {}
      }
    }
    try{
      for(int x = 0; items != null && x != items.length; x++)
      {
        char sign = (char)Integer.parseInt(items[x], 16);
        if(!deleteNullSigns || (deleteNullSigns && sign != 0) || x % 2 == 0) //dont delete every 0, just every 2nd step
          strRet.append(sign);
      }
    }
    catch(Exception ex){return hexCommaString;}
    //if i should delete 0 sign and the last sign is a hex 0 remove it!
    if(deleteNullSigns && strRet.charAt(strRet.length() - 1) == 0)
      strRet.deleteCharAt(strRet.length() - 1);
    return strRet.toString();
  }

  /***********************************************************************************************************************************
   * Method converts a plain String into a hex comma separated String with 0´s between
   * @param plain String
   * @param appendNullSigns boolean if you want to add null signs (needed for multi and expand entries, but not for binary entry)
   * @return String the converted string
   **********************************************************************************************************************************/
  public static String convertStringToHexComma(String plain, boolean appendNullSigns)
  {
    if(plain == null || plain.trim().length() == 0)
      return plain;
    StringBuffer strBuf = new StringBuffer();
    for(int x = 0; x != plain.length(); x++)
    {
      if(x > 0)
        strBuf.append(",");
      strBuf.append(Integer.toHexString(plain.charAt(x)));
      if(appendNullSigns)
        strBuf.append(",00"); //this is needed, dunno why by the multi and expand string entries, but not for the binary
    }
    return strBuf.toString();
  }

  /**
   *
   * @param plain String
   * @return String
   */
  private static String convertStringToHex(String plain)
  {
    if(plain == null || plain.trim().length() == 0)
      return plain;
    StringBuffer strBuf = new StringBuffer();
    for(int x = 0; x != plain.length(); x++)
    {
      strBuf.append(Integer.toHexString(plain.charAt(x)));
    }
    return strBuf.toString();
  }

  /******************************************************************************************************************************
   * intern method which obtain the methods via reflection from the java.util.prefs.WindowPreferences (tested with java 1.4, 1.5
   * and java 1.6)
   * @throws RegistryErrorException exception is thrown if any method is not found or if the class is not found
   *****************************************************************************************************************************/
  private void initMethods() throws RegistryErrorException
  {
    Class clazz = null;
    try
    {
      clazz = Class.forName("java.util.prefs.WindowsPreferences"); //you cannot access the class directly, cause its private
      Method ms[] = clazz.getDeclaredMethods();
      if(ms == null)
        throw new RegistryErrorException("Cannot access java.util.prefs.WindowsPreferences class!");
      //researching all methods to load it into the reflection methods
      for(int x = 0; x != ms.length; x++)
      {
        if(ms[x] != null)
        {
          if(ms[x].getName().equals("WindowsRegOpenKey"))
          {
            openKey = ms[x];
            openKey.setAccessible(true); //set Access for private
          }
          else if(ms[x].getName().equals("WindowsRegCloseKey"))
          {
            closeKey = ms[x];
            closeKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegCreateKeyEx"))
          {
            createKey = ms[x];
            createKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegDeleteKey"))
          {
            delKey = ms[x];
            delKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegFlushKey"))
          {
            flushKey = ms[x];
            flushKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegQueryValueEx"))
          {
            queryValue = ms[x];
            queryValue.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegSetValueEx"))
          {
            setValue = ms[x];
            setValue.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegDeleteValue"))
          {
            delValue = ms[x];
            delValue.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegQueryInfoKey"))
          {
            queryInfoKey = ms[x];
            queryInfoKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegEnumKeyEx"))
          {
            enumKey = ms[x];
            enumKey.setAccessible(true);
          }
          else if(ms[x].getName().equals("WindowsRegEnumValue"))
          {
            enumValue = ms[x];
            enumValue.setAccessible(true);
          }
        }
      }
    }
    catch (ClassNotFoundException ex)
    {
      throw RegistryErrorException.getException(ex);
    }
  }

  /**********************************************************************************************************************************
   * Method is looking for reg.exe or regedit.exe (first reg.exe if not found, take regedit.exe)
   * @throws RegistryErrorException throws this exception when no reg.exe or regedit.exe is found
   * @todo test vista UAC
   *********************************************************************************************************************************/
  private void initNatvieRegistry() throws RegistryErrorException
  {
    try{
      Runtime.getRuntime().exec("reg.exe"); //if no exception is thrown, then reg.exe was successfull
      nativeHandler = new RegHandler(); //reg.exe handler
    }
    catch(Exception ex)
    {
      //no check for regedit.exe because of vista uac control
      nativeHandler = new RegeditHandler();
    }
  }

  ///// caching methods starting here ////

  /**********************************************************************************************************************************
   * Method caches a complete key + 1 subkey
   * @param key Key the registry key which should be cached + subchildren
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void cacheKeys(Key key) throws RegistryErrorException
  {
    cacheKeys(key, 1);
  }


  /**********************************************************************************************************************************
   * Method caches a complete key tree (so the key + subchildren)
   * @param key Key the registry key which should be cached + subchildren
   * @param maximumChildren int amount of the subchildren which should be cached (attention, this may create a java.lang.OutofMemory
   * Error if you have not enoguth memory use -Xmx512M or sth)
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void cacheKeys(Key key, int maximumChildren) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(nativeHandler == null)
      throw new RegistryErrorException("NativeHandler is not initalized!");
    nativeHandler.cacheKeys(key.getPath(), maximumChildren);
  }

  /***********************************************************************************************************************************
   * Enables the caching method for dword, expand, multi and binary for the cacheKeys method and then for reading it
   * @param aValue boolean true or false
   **********************************************************************************************************************************/
  public void setCaching(boolean aValue)
  {
    if(useCache != aValue)
      useCache = aValue;
  }

  /***********************************************************************************************************************************
   * Returns if the caching for dword, expand, multi and binary is enabled (you have to use cacheKeys method)
   * @return boolean true or false (default = false)
   **********************************************************************************************************************************/
  public boolean isCachingActive()
  {
    return useCache;
  }

  /***********************************************************************************************************************************
   * Method returns all cached Keys
   * @return List a list of string of the cached key names
   **********************************************************************************************************************************/
  public List getCachingKeys()
  {
    List ret = null;
    if(isCachingActive() && caches != null && caches.size() > 0)
    {
      ret = new ArrayList();
      for(int x = 0; x != caches.size(); x++)
      {
        CachedEntry entry = (CachedEntry) caches.get(x);
        if(entry != null)
          ret.add(entry.getKey());
      }
    }
    return ret;
  }

  /**********************************************************************************************************************************
   * Method refreshes the cached entries
   * @todo implement 100% funtionality - i dont know the deepth search of the subkinds
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void refreshCaches() throws RegistryErrorException
  {
    if(isCachingActive())
    {
      if(caches != null && caches.size() > 0)
      {
        List tmpCache = (List) caches.clone();
        caches = new ArrayList();
        for (int x = 0; tmpCache != null && x != tmpCache.size(); x++)
        {
          CachedEntry entry = (CachedEntry) tmpCache.get(x);
          if (entry != null)
          {
            String key = entry.getKey();
            if(nativeHandler == null)
              throw new RegistryErrorException("NativeHandler is not initalized!");
            nativeHandler.cacheKeys(key, 1);
          }
        }

      }
    }
  }

  /**********************************************************************************************************************************
   * Method deletes all caching values
   *********************************************************************************************************************************/
  public void deleteCaches()
  {
    if(isCachingActive())
    {
      for (int x = 0; caches != null && x != caches.size(); x++)
      {
        CachedEntry entry = (CachedEntry) caches.get(x);
        if (entry != null)
        {
          List children = entry.getChildren();
          if (children != null)
            children.clear();
          List entries = entry.getEntries();
          if (entries != null)
            entries.clear();
        }
      }
      caches.clear();
      caches = null;
    }
  }

  /***********************************************************************************************************************************
   * Method searches for the key in the cache entry - just for private usage
   * @param key String
   * @param name String
   * @return String
   * @throws NoEntryException throws this exception if there is no such entry - returns null if it is not cached or caching is disabled
   **********************************************************************************************************************************/
  private String getCachedValue(String key, String name) throws NoEntryException
  {
    if(isCachingActive())
    {
      for(int x = 0; caches != null && x != caches.size(); x++)
      {
        CachedEntry entry = (CachedEntry) caches.get(x);
        CachedEntry child = entry.findSub(key);
        if(child != null)
        {
          List list = child.getEntries();
          if(list == null)
            throw new NoEntryException(key + " @ " + name + " not found in registry");
          for(int y = 0; list != null && y != list.size(); y++)
          {
            CachedValue val = (CachedValue)list.get(y);
            if(val != null)
            {
              if(val.getName().equals(name))
                return val.getData();
            }
          }
          if(list.size() > 0) //when the list has entries and the name is not found, then there is no such entry
            throw new NoEntryException(key + " @ " + name + " not found in registry");
        }
      }
    }
    return null;
  }

  /**********************************************************************************************************************************
   * Method change the cached values to the new entries
   * @param key String
   * @param name String
   * @param value String
   * @throws NoEntryException
   *********************************************************************************************************************************/
  private void setChachedValue(String key, String name, String value)
  {
    if(isCachingActive())
    {
      for(int x = 0; caches != null && x != caches.size(); x++)
      {
        CachedEntry entry = (CachedEntry) caches.get(x);
        CachedEntry child = entry.findSub(key);
        if(child != null)
        {
          List list = child.getEntries();
          for(int y = 0; list != null && y != list.size(); y++)
          {
            CachedValue val = (CachedValue)list.get(y);
            if(val != null)
            {
              if(val.getName().equals(name))
              {
                val.setData(value);
                break; //look up other cache entries
              }
            }
          }
        }
      }
    }
  }

  /**********************************************************************************************************************************
   * Method looks if the filesize becomes bigger after waiting some ms (which can be defined at WAIT_FOR_FILE)
   * @param file File
   *********************************************************************************************************************************/
  private static void _waitForFile(File file)
  {
    try{
      long size = file.length();
      Thread.sleep(WAIT_FOR_FILE);
      if(size != file.length())
        _waitForFile(file);
    }
    catch(Exception ex)
    {
      System.err.println("ERROR WAITING FOR FILE: " + file);
    }
  }

  /******************************************************************************************************************************
   * main for testing and some examples are stored here
   * @param args String[]
   * @throws Exception
   *****************************************************************************************************************************/
  public static void main(String[] args) throws Exception
  {
    Regor regor = new Regor();
    if(true)
    {
    	Key key = regor.openKey(HKEY_CURRENT_USER, "Software\\Adobe\\CommonFiles");
    	System.out.println(">>>!" + Regor.parseHexString(regor.readBinary(key, "BINARY"), false));
    	System.out.println(">>>!" + regor.readBinary(key, "BINARY"));
    	System.out.println(">>>RA!" + regor.readAnyValueString(key, "BINARY"));
    	System.out.println(">>>!" + Regor.parseHexString(regor.readAnyValueString(key, "BINARY"), false) + "!");
    	System.out.println(">>>>!" + Regor.parseHexString(regor.readDword(key, "PFERDA"), true));
    	System.out.println(">>>>!" + regor.readDword(key, "PFERDA"));
    	regor.closeKey(key);
    }
    Key _key = regor.openKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services");
//    regor.setCaching(true);
//    Key _key = regor.openKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\debis");
//    regor.cacheKeys(_key, 2);
    Key __key = regor.openKey(_key, "xmlprov");
//    System.out.println(">>> " + regor.getKeyType(__key, "Description"));
    System.out.println(">>1 " + regor.readAnyValueString(__key, "Description"));
    System.out.println(">>2 " + regor.readAnyValueString(__key, "dword"));
    System.out.println(">>3 " + regor.readAnyValueString(__key, "bla"));
    System.out.println(">>4 " + regor.readAnyValueString(__key, "bin2"));
    System.out.println(">>5 " + regor.readAnyValueString(__key, "expand2"));
    System.out.println(">>6 " + regor.readAnyValueString(__key, "multi"));

    System.out.println(">>>>MULTI1 " + regor.readMulti(__key,"multi"));
    System.out.println(">>>PARSEMULTI1 " + Regor.parseHexString(regor.readMulti(__key, "multi"), true));
    regor.savePlainMulti(__key, "multi", "WURSTSEMAL @ " + System.currentTimeMillis());
    System.out.println(">>>>MULTI2 " + regor.readMulti(__key,"multi"));
    System.out.println(">>>PARSEMULTI2 " + Regor.parseHexString(regor.readMulti(__key, "multi"), true));
    System.out.println(">>>>EXPAND " + regor.readExpand(__key,"expand"));
    System.out.println(">>>PARSEEXPAND " + Regor.parseHexString(regor.readExpand(__key, "expand"), true));
    System.out.println(">>>>DWORD " + regor.readDword(__key,"dword"));
    System.out.println(">>>PARSEDWORD " + Regor.parseHexString(regor.readMulti(__key, "dword"), true));
    System.out.println(">>>>BIN " + regor.readBinary(__key,"bin"));
    System.out.println(">>>PARSEBIN " + Regor.parseHexString(regor.readBinary(__key, "bin"), false));
//    regor.savePlainMulti(__key, "multi2", "%SystemRoot%\\System32\\svchost.exe -k netsvcs");
//    regor.savePlainExpand(__key, "expand2", "%SystemRoot%\\System32\\svchost.exe -k netsvcs");
//    regor.savePlainBinary(__key, "bin2", "%SystemRoot%\\System32\\svchost.exe -k netsvcs");
//    regor.cacheKeys(__key, 2);
    regor.closeKey(__key);
    regor.closeKey(_key);
    if(true)
      return;

    if(false) //testing the new methods
    {
      Key key = regor.openKey(HKEY_LOCAL_MACHINE, "Software\\AVS3");
//      regor.saveAnyValue("HKEY_LOCAL_MACHINE\\Software\\AVS3", "MULTI", MULTI_KEY,convertStringToHexComma("Das ist ein langer Test, mal schauen was da nachher rauskommt \n dumdidum!", true));
//      System.out.println(">>> " + Regor.parseHexString(regor.readMulti(key,"MULTI"), true));
//      System.out.println(">>> " + regor.readMulti(key, "MULTI"));
//      regor.saveDword(key, "DWOR1D", Integer.toHexString(23));
      regor.saveBinary(key, "BIN1", Regor.convertStringToHexComma("HALLO", false));
      System.out.println(">> " + regor.readBinary(key, "BIN1"));
      System.out.println(">>DW: " +regor.readDword(key, "DWORD"));
      regor.saveExpand(key, "MULTI3", Regor.convertStringToHexComma("DUMDIDUM", true));
      regor.closeKey(key);
      return;
    }
    //AT FIRST THE OLD WAY IS USED!!
    {
      System.out.println("NOW USING DEPRECATED REGOR!");
      //opening dhe LOCAL_MACHINE entry and software\microsoft - the delimiter is the \\
      int key = regor._openKey(_HKEY_LOCAL_MACHINE, "Software\\Microsoft"), key2 = -1;
      //listing the subkeys
      List l = regor._listKeys(key);
      System.out.println("SOME KEYS....");
      for (int x = 0; l != null && x != l.size(); x++) //printing out the keys
        System.out.println(x + " == " + l.get(x));
      if (l.size() > 0) //if keys found, use first key to get valueNames
        key2 = regor._openKey(key, (String) l.get(0));
      l = regor._listValueNames(key2); //read the valueNames
      System.out.println("SOME VALUENAMES.....");
      for (int x = 0; l != null && x != l.size(); x++) //printing it
        System.out.println(x + " == " + l.get(x));
      System.out.println("SOME STRING VALUES....");
      for (int x = 0; l != null && x != l.size(); x++) //getting the String value from the valueNames
      {
        byte buf[] = regor._readValue(key2, (String) l.get(x)); //get the information - if is not a string value, null will be returned
        System.out.println(x + ": " + l.get(x) + " == " + Regor.parseValue(buf)); //parses the byte buffer to String
      }
      //example to access the default valueName - either null or ""
      System.out.println("default entry == " + Regor.parseValue(regor._readValue(key, null)));
      //accessing a root node
      l = regor._listKeys(_HKEY_LOCAL_MACHINE);
      System.out.println("KEYS FROM LOCAL_MACHINE....");
      for (int x = 0; l != null && x != l.size(); x++) //printing out the keys
        System.out.println(x + " == " + l.get(x));
      regor._closeKey(key2);
      regor._closeKey(key);
    }

    //HERE THE NEW METHOD IS USED
    {
      System.out.println("NOW USING NEW REGOR!");
      Key key = regor.openKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft"), key2 = null;
      //listing the subkeys
      List l = regor.listKeys(key);
      System.out.println("SOME KEYS....");
      for (int x = 0; l != null && x != l.size(); x++) //printing out the keys
        System.out.println(x + " == " + l.get(x));
      if (l.size() > 0) //if keys found, use first key to get valueNames
        key2 = regor.openKey(key, (String) l.get(0));
      l = regor.listValueNames(key2); //read the valueNames
      System.out.println("SOME VALUENAMES.....");
      for (int x = 0; l != null && x != l.size(); x++) //printing it
        System.out.println(x + " == " + l.get(x));
      System.out.println("SOME STRING VALUES....");
      for (int x = 0; l != null && x != l.size(); x++) //getting the String value from the valueNames
      {
        byte buf[] = regor.readValue(key2, (String) l.get(x)); //get the information - if is not a string value, null will be returned
        System.out.println(x + ": " + l.get(x) + " == " + Regor.parseValue(buf)); //parses the byte buffer to String
      }
      //example to access the default valueName - either null or ""
      System.out.println("default entry == " + Regor.parseValue(regor.readValue(key, null)));
      //accessing a root node
      l = regor.listKeys(HKEY_LOCAL_MACHINE);
      System.out.println("KEYS FROM LOCAL_MACHINE....");
      for (int x = 0; l != null && x != l.size(); x++) //printing out the keys
        System.out.println(x + " == " + l.get(x));
      regor.closeKey(key2);
      regor.closeKey(key);
    }
  }

  //
  //Exception is used when searching with cached values and the cached values has no entries
  private final static class NoEntryException extends Exception
  {
	private static final long serialVersionUID = 1L;
    public NoEntryException(String str)
    {
      super(str);
    }
  }

  /////// DIRTY CLASSES STARTS HERE ////////////////////

  //Interface
  private interface INativeRegistryHandler
  {
    boolean saveAnyValue(String path, String valueName, String type, String data) throws RegistryErrorException;
    String extractAnyValue(String path, String valueName, boolean appendType) throws RegistryErrorException;
    void cacheKeys(String key, int maximumChildren) throws RegistryErrorException;
  }

  //intern class which uses regedit.exe (if not admin with vista, you cannot read values)
  private final class RegeditHandler implements INativeRegistryHandler
  {
    /********************************************************************************************************************************
     * Method saves any variable to the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
     * it would be the processbuilder)
     * @param path String the registy path (without [])
     * @param valueName String the valuename to set
     * @param type String the type (BINARY, DWORD, MULTI, EXPAND)
     * @param data String  the data which should be stored in the registry (it must be converted into the right format for the given type)
     * @return boolean returns always true (otherwhise exceptio is thrown) - maybe better use in future
     * @throws RegistryErrorException
     *******************************************************************************************************************************/
    public boolean saveAnyValue(String path, String valueName, String type, String data) throws RegistryErrorException
    {
      try{
        File f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
        //now writing the file for registry import
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f)));
        bw.write(INIT_WINDOWS_STRING);
        bw.newLine();
        bw.newLine();
        bw.write("[");
        bw.write(path);
        bw.write("]");
        bw.newLine();
        bw.write("\"");
        bw.write(valueName);
        bw.write("\"=");
        bw.write(type);
        bw.write(data);
        bw.newLine();
        bw.close();
        //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
        Runtime.getRuntime().exec("regedit /s /i " + f.getAbsolutePath()).waitFor(); //<-- Waiting for END of Process
        if(!f.delete()) //if delete has no success
          f.deleteOnExit(); //mark it, for delete on exit
        setChachedValue(path, valueName, data);
      }
      catch(Exception ex)
      {
        System.err.println(ex.getLocalizedMessage());
//      ex.printStackTrace(System.out);
        throw RegistryErrorException.getException(ex);
      }
      return true;
    }

    /**********************************************************************************************************************************
     * Method extracts any variable from the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
     * it would be the processbuilder)
     * @param path String the registry path to the parent key
     * @param valueName String the valuename which should be read from the registry key
     * @param appendType boolean if the method should append the type - not needed with regedit.exe method, because the type is always
     * added
     * @return String null if the valuename is not found or the path could not be exported - otherwhise the data from the registry
     * @throws RegistryErrorException
     *********************************************************************************************************************************/
    public String extractAnyValue(String path, String valueName, boolean appendType) throws RegistryErrorException
    {
      try{
        String tmp = getCachedValue(path, valueName);
        if (tmp != null)
        {
//          System.out.println("FOUND CACHED!");
          return tmp;
        }
        else if (useCache)
          System.out.println("CACHED KEY: " + path + " AND VALUE NOT FOUND: " + valueName);
      }
      catch(NoEntryException nee) //has not this children
      {
        if(isCachingActive()) //only if caching is active
          return null;
      }
      StringBuffer strRet = new StringBuffer(); //stringbuffer for appending, if an entry has multiplie lines
      File f = null;
      BufferedReader br = null;
      try{
        f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
        //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
        Runtime.getRuntime().exec("regedit /e " + f.getAbsolutePath() + " \"" + path + "\"").waitFor(); //<-- WAITING FOR END OF PROCESS
        _waitForFile(f); //wait until the file size is not increasing anymore
        br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
        String line = "";
        boolean lineFound = false, keyFound = false;
        while ( ( line = br.readLine() ) != null)
        {
          line = line.replaceAll(NULL_STRING,"");
          if(line.length() > 0)
          {
            if (keyFound ||  (line.startsWith("[") && line.endsWith("]")) )
            {
              if(line.startsWith("[") && line.endsWith("]"))
              {
                if(keyFound) //abort if new key starts
                  break;
                else{
                  if(line.equals("[" + path + "]")) //if the line is the same then start searching for your value
                    keyFound = true;
                }
              }
              else if(keyFound && ( lineFound || line.startsWith("\"" + valueName) && line.indexOf("=") != -1  ))
              {
                if(lineFound) //when line found, just append
                {
                  if(line.length() > 0)
                  {
                    if (line.indexOf("=") != -1) //if = is found, this is a new item so abort
                    {
                      break;
                    }
                    //and append the line, if its for the same item
                    strRet.append(line.trim().replaceAll("\\\\", "")); //eliminate every \
                    if(!line.endsWith("\\")) //if line doesnt ends with \ the registry entry has no more lines
                    {
                      break;
                    }
                  }
                }
                else
                {
                  line = line.substring(line.indexOf("=") + 1);
                  strRet.append(line.replaceAll("\\\\","")); //eliminate every \ also if there is none
                  lineFound = true;
                  if (line.indexOf("\\") == -1) //if no \\ is found, there is no new line in the string, so abort
                  {
                    break; //abort if no \ is found
                  }
                }
              }
            }
          }
        }
        br.close(); //close reader, so that you can delete the file
        if(!f.delete()) //if delete has no success
          f.deleteOnExit(); //mark it, for delete on exit
      }
      catch(Exception ex)
      {
        System.err.println(ex.getLocalizedMessage());
//      ex.printStackTrace(System.out);
        throw RegistryErrorException.getException(ex);
      }
      finally{
        try{
          if(br != null)
            br.close(); //close reader, so that you can delete the file
        }
        catch(Exception ex){}
        if(f != null)
          if(!f.delete()) //if delete has no success
            f.deleteOnExit(); //mark it, for delete on exit
      }
      //if the buffer length is zero, return null
      return strRet.length() == 0  ? null : strRet.toString();
    }

    /**********************************************************************************************************************************
     * Method caches a complete key tree (so the key + subchildren)
     * @param key String the registry key which should be cached + subchildren
     * @param maximumChildren int amount of the subchildren which should be cached (attention, this may create a java.lang.OutofMemory
     * Error if you have not enoguth memory use -Xmx512M or sth)
     * @throws RegistryErrorException
     *********************************************************************************************************************************/
    public void cacheKeys(String key, int maximumChildren) throws RegistryErrorException
    {
      StringBuffer strRet = new StringBuffer(); //stringbuffer for appending, if an entry has multiplie lines
      try{
        File f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
//      long stamp1 = System.currentTimeMillis();
        //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
        Runtime.getRuntime().exec("regedit /e " + f.getAbsolutePath() + " \"" + key + "\"").waitFor(); //<-- WAITING FOR END OF PROCESS
        _waitForFile(f); //wait until the file size is not increasing anymore
//      System.out.println(">>> NEEDED: " + (System.currentTimeMillis() - stamp1) + " " + f.getAbsolutePath());
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
        String line = "";
        CachedEntry entry = new CachedEntry(), currentEntry = null;
        CachedValue currentValue = null;
        entry.setKey(key);
        while ( ( line = br.readLine() ) != null)
        {
          line = line.replaceAll(NULL_STRING,""); //remove illegale signs
          if(line != null && line.length() > 0)
          {
            if(line.startsWith("[") && line.endsWith("]")) //
            {
              if(currentEntry != null) //if there was a key
              {
                Object tmp[] = entry.getSub(currentEntry.getKey());
                if(tmp != null)
                {
                  //just append the data if the maximumchildren is not higher as given
                  if ( ( (Integer) tmp[1]).intValue() < maximumChildren)
                    ((CachedEntry)tmp[0]).appendChildren(currentEntry);
                }
                currentEntry = null;
              }
              String currentKey = line.substring(1, line.length() - 1); //gets the current key
              //if not null and bigger than 0 and if is not the main key
              if(currentKey != null  && currentKey.length() > 0)
              {
                //when it is the main key, then you should store it settings at the main key
                if (currentKey.equals(entry.getKey()))
                  currentEntry = entry;
                else
                {
                  currentEntry = new CachedEntry();
                  currentEntry.setKey(currentKey);
                }
              }
            }
            //if currentEntry is opened and either equals is in the line or it is more than one line
            else if(currentEntry != null && (line.indexOf("=") != -1 || currentValue != null))
            {
              if(currentValue != null) //when line found, just append
              {
                if(line.length() > 0)
                {
                  if (line.indexOf("=") != -1) //if = is found, this is a new item so abort
                  {
                    currentValue.setData(strRet.toString());
//                  currentValue.setData(parseData(strRet.toString()));
                    strRet.delete(0, strRet.length());
                    currentEntry.appendEntry(currentValue);
                    currentValue = null;
                  }
                  else               //and append the line, if its for the same item
                  {
                    line = line.trim();
                    if(line.endsWith("\\"))
                      strRet.append(line.substring(0, line.length() - 1));
                    else
                    {
                      strRet.append(line.trim());
//                  }
//                  if (!line.endsWith("\\")) //if line doesnt ends with \ the registry entry has no more lines
//                  {
                      currentValue.setData(strRet.toString());
//                    currentValue.setData(parseData(strRet.toString()));
                      strRet.delete(0, strRet.length());
                      currentEntry.appendEntry(currentValue);
                      currentValue = null;
                    }
                  }
                }
              }
              else
              {
                String currentName = line.substring(0,line.indexOf("="));
                //default name
                if(currentName.equals("@"))
                  currentName = "";
                currentValue = new CachedValue();
                currentValue.setName(currentName.replaceAll("\"",""));
                line = line.substring(line.indexOf("=") + 1);
                if(line.endsWith("\\"))
                  strRet.append(line.substring(0, line.length() - 1));
                else
                {
                  strRet.append(line);
//              }
//              if (line.indexOf("\\") == -1) //if no \\ is found, there is no new line in the string, so abort
//              {
                  currentValue.setData(strRet.toString());
//                currentValue.setData(parseData(strRet.toString()));
                  strRet.delete(0, strRet.length());
                  currentEntry.appendEntry(currentValue);
                  currentValue = null;
                }
              }
            }
          }
        }
        if(currentEntry != null) //if there was a key
        {
          Object tmp[] = entry.getSub(currentEntry.getKey());
          if(tmp != null)
          {
            //just append the data if the maximumchildren is not higher as given
            if ( ( (Integer) tmp[1]).intValue() < maximumChildren)
              ( (CachedEntry) tmp[0]).appendChildren(currentEntry);
          }
        }
        br.close(); //close reader, so that you can delete the file
        if(!f.delete()) //if delete has no success
          f.deleteOnExit(); //mark it, for delete on exit
        if(caches == null)
          caches = new ArrayList();
        caches.add(entry);
      }
      catch(Exception ex)
      {
//      ex.printStackTrace(System.out);
        System.err.println(ex.getLocalizedMessage());
        throw RegistryErrorException.getException(ex);
      }
    }
  }

  //Intern class which uses reg.exe to handle with the registry (more vista safe)
  private final class RegHandler implements INativeRegistryHandler
  {
    /********************************************************************************************************************************
     * Method saves any variable to the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
     * it would be the processbuilder)
     * @param path String the registy path (without [])
     * @param valueName String the valuename to set
     * @param type String the type (BINARY, DWORD, MULTI, EXPAND)
     * @param data String  the data which should be stored in the registry (it must be converted into the right format for the given type)
     * @return boolean returns always true (otherwhise exceptio is thrown) - maybe better use in future
     * @throws RegistryErrorException
     *******************************************************************************************************************************/
    public boolean saveAnyValue(String path, String valueName, String type, String data) throws RegistryErrorException
    {
      try{
        if(type.equals(BINARY_KEY_IDENT))
          type = "REG_BINARY";
        else if(type.equals(DWORD_KEY_IDENT))
          type = "REG_DWORD";
        else if(type.equals(MULTI_KEY_IDENT))
          type = "REG_MULTI_SZ";
        else if(type.equals(EXPAND_KEY_IDENT))
          type = "REG_EXPAND_SZ";
        Runtime.getRuntime().exec("reg add \"" + path + "\" /v \"" + valueName + "\" /t " + type + " /d \"" + data + "\" /f");
        setChachedValue(path, valueName, data);
      }
      catch(Exception ex)
      {
//        ex.printStackTrace(System.out);
        System.err.println(ex.getLocalizedMessage());
        throw RegistryErrorException.getException(ex);
      }
      return true;
    }

    /**********************************************************************************************************************************
     * Method extracts any variable from the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
     * it would be the processbuilder)
     * @param path String the registry path to the parent key
     * @param valueName String the valuename which should be read from the registry key
     * @param appendType boolean add the type to the return string
     * @return String null if the valuename is not found or the path could not be exported - otherwhise the data from the registry
     * @throws RegistryErrorException
     *********************************************************************************************************************************/
    public String extractAnyValue(String path, String valueName, boolean appendType) throws RegistryErrorException
    {
      try{
        String tmp = getCachedValue(path, valueName);
        if (tmp != null)
        {
//          System.out.println("FOUND CACHED!");
          return tmp;
        }
        else if (useCache)
          System.out.println("CACHED KEY: " + path + " AND VALUE NOT FOUND: " + valueName);
      }
      catch(NoEntryException nee) //has not this children
      {
        if(isCachingActive()) //only if caching is active
          return null;
      }
      StringBuffer strRet = new StringBuffer(); //stringbuffer for appending, if an entry has multiplie lines
      BufferedReader br = null;
      File f = null;
      try{
        f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
        //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
        Runtime.getRuntime().exec("cmd /c \"reg query \"" + path + "\" /v \"" + valueName + "\" > " + f.getAbsolutePath() + " 2>&1\"").waitFor(); //<-- WAITING FOR END OF PROCESS
        _waitForFile(f); //wait until the file size is not increasing anymore
        br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
        String line = "";
        boolean lineFound = false;
        while ( ( line = br.readLine() ) != null)
        {
          if(line.equals(path))
          {
            lineFound = true;
          }
          else if(lineFound && line.trim().length() > 0)
          {
            StringTokenizer st = new StringTokenizer(line, " \t");
            String[] items = {"","",""};
            
            int i = 0;
            while(st.hasMoreTokens()){
              items[i] += st.nextToken() + " ";
              if(i<2){
                i++;
              }
            }
            for(int j = 0; j<items.length;j++){
              items[j] = items[j].trim(); 
            }
            
            
            if(items[0].equals(valueName))
            {
              if(appendType)
              {
                strRet.append(items[1]);
                strRet.append(" ");
              }
              //[0] = type
              //[1] = entry
/*              if (items[0].equals("REG_MULTI_SZ"))
                strRet.append(MULTI_KEY); //add this for older version
              else if (items[0].equals("REG_EXPAND_SZ"))
                strRet.append(EXPAND_KEY);
              else if (items[0].equals("REG_DWORD"))
                strRet.append(DWORD_KEY);
              else if (items[0].equals("REG_BINARY"))
                strRet.append(BINARY_KEY);*/
              strRet.append(items[2]);
              if(items[1].equals("REG_MULTI_SZ") && strRet.toString().endsWith("\\0\\0"))
                strRet.setLength(strRet.length() - 4);
              break;
            }
          }
        }
      }
      catch(Exception ex)
      {
//        ex.printStackTrace(System.out);
        System.err.println(ex.getLocalizedMessage());
        throw RegistryErrorException.getException(ex);
      }
      finally{
        try{
          if(br != null)
            br.close(); //close reader, so that you can delete the file
        }
        catch(Exception ex){}
        if(f != null)
          if(!f.delete()) //if delete has no success
            f.deleteOnExit(); //mark it, for delete on exit
      }
      return strRet.toString();
    }

    /**********************************************************************************************************************************
     * Method caches a complete key tree (so the key + subchildren)
     * @param key String the registry key which should be cached + subchildren
     * @param maximumChildren int amount of the subchildren which should be cached (attention, this may create a java.lang.OutofMemory
     * Error if you have not enoguth memory use -Xmx512M or sth)
     * @throws RegistryErrorException
     *********************************************************************************************************************************/
    public void cacheKeys(String key, int maximumChildren) throws RegistryErrorException
    {
      File f = null;
      BufferedReader br = null;
      try{
        f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
        //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
        Runtime.getRuntime().exec("cmd /c \"reg query \"" + key + "\" /s > " + f.getAbsolutePath() + " 2>&1\"").waitFor(); //<-- WAITING FOR END OF PROCESS
        _waitForFile(f); //wait until the file size is not increasing anymore
        br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
        String line = "";
        CachedEntry entry = new CachedEntry(), currentEntry = null;
        String currentKey = null;
        entry.setKey(key);
        while ( ( line = br.readLine() ) != null)
        {
          if(line.trim().length() > 0) //if found and not empty line
          {
            if(line.startsWith("HKEY_")) //if starts with hkey its an entry name
            {
              if(currentEntry != null)
              {
                Object tmp[] = entry.getSub(currentEntry.getKey());
                if(tmp != null)
                {
                  //just append the data if the maximumchildren is not higher as given
                  if ( ( (Integer) tmp[1]).intValue() < maximumChildren)
                    ((CachedEntry)tmp[0]).appendChildren(currentEntry);
                }
              }
              currentEntry = null;
              currentKey = line; //its the current Key
              if(currentKey != null  && currentKey.length() > 0)
              {
                //when it is the main key, then you should store it settings at the main key
                if (currentKey.equals(entry.getKey()))
                  currentEntry = entry;
                else
                {
                  currentEntry = new CachedEntry();
                  currentEntry.setKey(currentKey);
                }
              }
            }
            //if currentEntry is opened
            else if(currentEntry != null && !line.startsWith("Error:  ")) //else its a value and if it doesnet starts with Error:
            {
              StringBuffer strRet = new StringBuffer();
              int regIndex = line.indexOf("\tREG_"); //always is \tREG
              int adding = 5;
              if(regIndex == -1)
              {
              	regIndex = line.indexOf("    REG_");
              	adding = 4;
              }
              String valueName = line.substring(4, regIndex);
              line = line.substring(regIndex + adding);
              String items[] = line.split("\\s+",2); //last 2 tokens
              //[0] = type
              //[1] = entry
/*              if(items[0].equals("REG_MULTI_SZ"))
                strRet.append(MULTI_KEY); //add this for older version
              else if(items[0].equals("REG_EXPAND_SZ"))
                strRet.append(EXPAND_KEY);
              else if(items[0].equals("REG_DWORD"))
                strRet.append(DWORD_KEY);
              else if(items[0].equals("REG_BINARY"))
                strRet.append(BINARY_KEY);*/
              strRet.append(items[1]);
              CachedValue currentValue = new CachedValue();
              if(valueName.equals("<NO NAME>")) //this is the default entry
                currentValue.setName("");
              else
                currentValue.setName(valueName);
              currentValue.setData(strRet.toString());
              currentEntry.appendEntry(currentValue);
            }
          }
        }
        //for the last entry
        if(currentEntry != null) //if there was a key
        {
          Object tmp[] = entry.getSub(currentEntry.getKey());
          if(tmp != null)
          {
            //just append the data if the maximumchildren is not higher as given
            if ( ( (Integer) tmp[1]).intValue() < maximumChildren)
              ( (CachedEntry) tmp[0]).appendChildren(currentEntry);
          }
        }
        if(caches == null)
          caches = new ArrayList();
        caches.add(entry);
      }
      catch(Exception ex)
      {
//        ex.printStackTrace(System.out);
        System.err.println(ex.getLocalizedMessage());
        throw RegistryErrorException.getException(ex);
      }
      finally{
        try{
          if(br != null)
            br.close(); //close reader, so that you can delete the file
        }
        catch(Exception ex){}
        if(f != null)
          if(!f.delete()) //if delete has no success
            f.deleteOnExit(); //mark it, for delete on exit
      }
    }
  }
}
