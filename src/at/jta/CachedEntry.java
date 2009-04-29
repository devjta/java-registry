package at.jta;

import java.util.List;
import java.util.ArrayList;


/************************************************************************************************************************************
 * <p>Title: New class for cashing the registry </p>
 *
 * <p>Description: class has the cashed entries + children  - final protected class not for public usage</p>
 *
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 1.0 15.10.2008
 ***********************************************************************************************************************************/
final class CachedEntry
{
  private List children;
  private List entries;
  private String key;
  private String _key;

  /**
   * default constructor
   */
  public CachedEntry()
  {
    super();
  }

  /**
   *
   * @param child CachedEntry
   */
  protected void appendChildren(CachedEntry child)
  {
    if(children == null)
      children = new ArrayList();
    children.add(child);
  }

  /**
   *
   * @param entry CachedValue
   */
  protected void appendEntry(CachedValue entry)
  {
    if(entries == null)
      entries = new ArrayList();
    entries.add(entry);
  }

  /**
   *
   * @param key String
   * @return Object[] [0] = CachedEntry [1] = childstep
   */
  protected Object[] getSub(String key)
  {
    return getSub(key, 0);
  }

  /**
   *
   * @param key String
   * @param step int
   * @return Object[]
   */
  private Object[] getSub(String key, int step)
  {
    if(children != null)
    {
      for (int x = children.size() - 1; x >= 0; x--)
      {
        CachedEntry tmp = (CachedEntry) children.get(x);
        if(key.startsWith(tmp._getKey()))
        {
          return tmp.getSub(key, ++step);
        }
      }
    }
    if(!key.startsWith(_getKey()))
      return null;
    return new Object[]{this, new Integer(step)};
  }

  /**
   *
   * @param key String
   * @return CachedEntry
   */
  protected CachedEntry findSub(String key)
  {
    if(!key.startsWith(getKey()))
      return null;
    if(children != null)
    {
      for (int x = children.size() - 1; x >= 0; x--)
      {
        CachedEntry tmp = (CachedEntry) children.get(x);
        if(key.startsWith(tmp.getKey()))
        {
          return tmp.findSub(key);
        }
      }
    }
    if(!getKey().startsWith(key))
      return null;
    return this;
  }

  private String _getKey()
  {
    return _key;
  }

  public List getChildren()
  {
    return children;
  }

  public List getEntries()
  {
    return entries;
  }

  public String getKey()
  {
    return key;
  }

  public void setKey(String key)
  {
    this.key = key;
    this._key = key + "\\";
  }

  /**
   *
   * @return String
   */
  public String toString()
  {
    return new StringBuffer("CachedEntry Key: ").append(getKey()).append(" Entries: ").append(getEntries()).append(" Children: ").append(getChildren()).toString();
  }
}
