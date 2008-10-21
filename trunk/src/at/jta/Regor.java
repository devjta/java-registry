package at.jta;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.ArrayList;
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
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:joerg_t_p@gmx.at">Taschek Joerg</a>
 * @version 2.0 22.03.2007 Methods are renamed and now called by the function they are implementing and the document is now in
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
 *******************************************************************************************************************************/
final public class Regor
{
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
  private static final String BINARY_KEY = "hex:";

  /**
   * Every dword entry starts with this, also used for import
   */
  private static final String DWORD_KEY = "dword:";

  /**
   * Every multi string entry starts with this, also used for import
   */
  private static final String MULTI_KEY = "hex(7):";

  /**
   * Every expand string entry starts with this, also used for import
   */
  private static final String EXPAND_KEY = "hex(2):";


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

  /******************************************************************************************************************************
   * Constructor to handle with windows registry
   * @throws RegistryErrorException throws an registryerrorException when its not able to get a handle to the registry methods
   * @throws NotSupportedOSException throws an notSupportedOSException if the registry is not used in windows
   *****************************************************************************************************************************/
  public Regor() throws RegistryErrorException
  {
    checkOS();
    initMethods();
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

  /**********************************************************************************************************************************
   * Method saves any variable to the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
   * it would be the processbuilder)
   * @param path String the registy path (without [])
   * @param valueName String the valuename to set
   * @param type String the type (BINARY, DWORD, MULTI, EXPAND)
   * @param data String  the data which should be stored in the registry (it must be converted into the right format for the given type)
   * @return boolean returns always true (otherwhise exceptio is thrown) - maybe better use in future
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  private boolean saveAnyValue(String path, String valueName, String type, String data) throws RegistryErrorException
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
    }
    catch(Exception ex)
    {
      System.err.println(ex.getLocalizedMessage());
//      ex.printStackTrace(System.out);
      throw new RegistryErrorException(ex.getLocalizedMessage());
    }
    return true;
  }

  /**********************************************************************************************************************************
   * Method extracts any variable from the registry via the regedit.exe and runtime - because its java 1.4 compatbile (otherwhise
   * it would be the processbuilder)
   * @param path String the registry path to the parent key
   * @param valueName String the valuename which should be read from the registry key
   * @return String null if the valuename is not found or the path could not be exported - otherwhise the data from the registry
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  private String extractAnyValue(String path, String valueName) throws RegistryErrorException
  {
    try{
      String tmp = getCachedValue(path, valueName);
      if (tmp != null)
        return tmp;
      else if (useCache)
        System.out.println("CACHED KEY: " + path + " AND VALUE NOT FOUND: " + valueName);
    }
    catch(NoEntryException nee) //has not this children
    {
      if(isCachingActive()) //only if caching is active
        return null;
    }
    StringBuffer strRet = new StringBuffer(); //stringbuffer for appending, if an entry has multiplie lines
    try{
      File f = File.createTempFile("regorexp",".jta"); //creates tmp File for storing the registry key
      //ATTENTION!! THESE COULD BE A DEADLOCK BECAUSE I WAITFOR THE END OF PROCESS HERE
      Runtime.getRuntime().exec("regedit /e " + f.getAbsolutePath() + " \"" + path + "\"").waitFor(); //<-- WAITING FOR END OF PROCESS
      _waitForFile(f); //wait until the file size is not increasing anymore
      BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
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
      throw new RegistryErrorException(ex.getLocalizedMessage());
    }
    //if the buffer length is zero, return null
    return strRet.length() == 0  ? null : strRet.toString();
  }

  /***********************************************************************************************************************************
   * Method saves a binary entry for the given key, valuename and data
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
    saveAnyValue(key.getPath(), valueName, BINARY_KEY, hexCommaData);
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
    String ret = extractAnyValue(key.getPath(), valueName);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(BINARY_KEY))
    {
      return ret.substring(4);
    }
    return null;
  }

  /**********************************************************************************************************************************
   * Method saves a dword entry in the registry
   * @since version 3 (03.06.2008)
   * @see <code>saveAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the valuename of the dword entry
   * @param hexData String a hexadecimal String withouth comma or spaces (use <code>Integer.toHexString()</code> to get a hex string)
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public void saveDword(Key key, String valueName, String hexData) throws RegistryErrorException
  {
    saveAnyValue(key.getPath(), valueName, DWORD_KEY, hexData);
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
    String ret = extractAnyValue(key.getPath(), valueName);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(DWORD_KEY))
    {
      return ret.substring(6);
    }
    return null;
  }

  /***********************************************************************************************************************************
   * Method saves a multi string entry in the registry
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
    saveAnyValue(key.getPath(), valueName, MULTI_KEY, hexCommaZeroData);
  }

  /**********************************************************************************************************************************
   * Method reads a multi string entry from the registry
   * @since version 3 (03.06.2008 - my dad has birthday ;))
   * @see <code>extractAnyValue</code> - method could have a deadlock
   * @param key Key the parent key handle obtained by openKey
   * @param valueName String the multi value name
   * @return String the HEXADECIMAL values separated by comma (use <code>String parseHexString(String)</code> to convert it
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  public String readMulti(Key key, String valueName) throws RegistryErrorException
  {
    if(key == null)
      throw new NullPointerException("Registry key cannot be null");
    if(valueName == null)
      throw new NullPointerException("Valuename cannot be null, because the default value is always a STRING! If you want to read a String use readValue");
    String ret = extractAnyValue(key.getPath(), valueName);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(MULTI_KEY))
    {
      return ret.substring(7);
    }
    return null;
  }

  /**********************************************************************************************************************************
   * Method saves an expand string entry
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
    saveAnyValue(key.getPath(), valueName, EXPAND_KEY, hexCommaZeroData);
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
    String ret = extractAnyValue(key.getPath(), valueName);
    //if it is not null and it starts with hex: it is hopefully a binary entry
    if(ret != null && ret.startsWith(EXPAND_KEY))
    {
      return ret.substring(7);
    }
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
    return listKeys(key,null);
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
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
  }

  /******************************************************************************************************************************
   * Method deletes the specified value (YOU CAN ALSO DELETE BINARY, DWORD, MULTI OR EXPAND ENTRIES!!!)
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
   * deleted)
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalArgumentException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
    }
    catch (IllegalAccessException ex)
    {
      throw new RegistryErrorException(ex.getMessage());
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
      throw new RegistryErrorException(ex1.getMessage());
    }
    catch (IllegalArgumentException ex1)
    {
      throw new RegistryErrorException(ex1.getMessage());
    }
    catch (IllegalAccessException ex1)
    {
      throw new RegistryErrorException(ex1.getMessage());
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
    //if no comma was found, return the given string
    if(items == null || items.length == 0)
      return hexCommaString;
    StringBuffer strRet = new StringBuffer();
    for(int x = 0; items != null && x != items.length; x++)
    {
      char sign = (char)Integer.parseInt(items[x], 16);
      if(!deleteNullSigns || (deleteNullSigns && x % 2 == 1 & sign != 0)) //dont delete every 0, just every 2nd step
        strRet.append(sign);
    }
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
      throw new RegistryErrorException(ex.getMessage());
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
    cacheKeys(key.getPath(), maximumChildren);
  }

  /**********************************************************************************************************************************
   * Method caches a complete key tree (so the key + subchildren)
   * @param key String the registry key which should be cached + subchildren
   * @param maximumChildren int amount of the subchildren which should be cached (attention, this may create a java.lang.OutofMemory
   * Error if you have not enoguth memory use -Xmx512M or sth)
   * @throws RegistryErrorException
   *********************************************************************************************************************************/
  private void cacheKeys(String key, int maximumChildren) throws RegistryErrorException
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
      throw new RegistryErrorException(ex.getLocalizedMessage());
    }
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
            cacheKeys(key, 1);
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
   * Method parses the data for caching - not used anymore
   * @param data String
   * @return String
   *********************************************************************************************************************************/
  private static String parseData(String data)
  {
    if(data == null || data.length() == 0)
      return data;
    if(data.startsWith(BINARY_KEY))
      return data.substring(4);
//      return parseHexString(data.substring(4), false);
    else if(data.startsWith(DWORD_KEY))
      return data.substring(6);
//      return parseHexString(data.substring(6), false);
    else if(data.startsWith(MULTI_KEY))
      return data.substring(7);
//      return parseHexString(data.substring(7), true);
    else if(data.startsWith(EXPAND_KEY))
      return data.substring(7);
//      return parseHexString(data.substring(7), true);
    else if(data.startsWith("\""))
      return data.replaceAll("\"", "");
    return data;
  }

  /**********************************************************************************************************************************
   * Method looks if the filesize becomes bigger after waiting some ms (which can be defined at WAIT_FOR_FILE)
   * @param file File
   *********************************************************************************************************************************/
  private static void _waitForFile(File file)
  {
    try{
      long size = file.length();
      Thread.currentThread().sleep(WAIT_FOR_FILE);
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
    Key _key = regor.openKey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services");
//    regor.setCaching(true);
//    Key _key = regor.openKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\debis");
    regor.cacheKeys(_key, 2);
    Key __key = regor.openKey(_key, "xmlprov\\Parameters");
    System.out.println("KEY:: " + __key);
//    System.out.println(">> " + regor.readExpand(__key, "ServiceDll"));
//    System.out.println(">>> " + Regor.parseHexString(regor.readExpand(__key, "ServiceDll"), true));
    System.out.println(">>>> " + regor.readMulti(_key,"DependOnService"));
    System.out.println(">>> " + Regor.parseHexString(regor.readMulti(_key, "DependOnService"), true));
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
  private static class NoEntryException extends Exception
  {
    public NoEntryException(String str)
    {
      super(str);
    }
  }
}
