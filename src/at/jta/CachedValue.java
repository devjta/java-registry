package at.jta;

/************************************************************************************************************************************
 * <p>Title: New class for cashing the registry </p>
 *
 * <p>Description: Class has the cached values - final protected class not for public usage</p>
 *
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 1.0 15.10.2008
 ***********************************************************************************************************************************/
final class CachedValue
{
  private String name;
  private String data;

  public CachedValue()
  {

  }

  public String getData()
  {
    return data;
  }

  public String getName()
  {
    return name;
  }

  public void setData(String data)
  {
    this.data = data;
  }

  public void setName(String name)
  {
    this.name = name;
  }

  public String toString()
  {
    return new StringBuffer("CachedValue Name: ").append(getName()).append(" Data: ").append(getData()).toString();
  }
}
