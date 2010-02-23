package at.jta;

/********************************************************************************************************************************
 *
 * <p>Title: Exception is thrown if you use the regor class on not windows machines </p>
 *
 * <p>Description: </p>
 *
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 1.0
 *******************************************************************************************************************************/
final public class NotSupportedOSException
    extends RuntimeException
{
  private static final long serialVersionUID = 1L;
  
  /******************************************************************************************************************************
   * Constructor with message to throw
   * @param str String
   *****************************************************************************************************************************/
  public NotSupportedOSException(String str)
  {
    super(str);
  }
}
