package at.jta;

/************************************************************************************************************************************
 * <p>Title: New class instead of int key to store the path </p>
 *
 * <p>Description: </p>
 *
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 1.0 First version 03.06.08 (my dads birthday, hurray ;))
 ***********************************************************************************************************************************/
final public class Key
{
  private String path;
  private int key;

  /**
   * Default constructor
   */
  public Key()
  {
  }

  /**
   * Constructor with the index key and the path
   * @param key int
   * @param path String
   */
  public Key(int key, String path)
  {
    setKey(key);
    setPath(path);
  }

  /**
   * Constructor used by the class Regor and the open key method, to open a child key
   * @param parentKey Key to get the parent path and append the new subpath
   * @param key int the key handle
   * @param subPath String subpath which will be append to the parent path
   */
  protected Key(Key parentKey, int key, String subPath)
  {
    setKey(key);
    setPath(parentKey.getPath() + "\\" + subPath);
  }

  public int getKey()
  {
    return key;
  }

  public String getPath()
  {
    return path;
  }

  public void setKey(int key)
  {
    this.key = key;
  }

  public void setPath(String path)
  {
    this.path = path;
  }

  public String toString()
  {
    return new StringBuffer("Key: ").append(getKey()).append(" Path: ").append(getPath()).toString();
  }

  /**
   * Method looks up the key and determine if it is an valid key (not -1) or not
   * @return boolean
   */
  public boolean _isValidKey()
  {
    return getKey() != -1;
  }
}
