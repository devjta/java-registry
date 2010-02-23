package at.jta;

/*******************************************************************************************************************************
 *
 * <p>Title: class for throwing exceptions </p>
 *
 * <p>Description: </p>
 *
 * <p>Copyright: Copyright (c) 2008 - class is under GPL and LGPL</p>
 *
 * <p>Company: Taschek Joerg</p>
 *
 * @author <a href="mailto:behaveu@gmail.com">Taschek Joerg</a>
 * @version 1.0
 * @version 2.0 29.04.2009 Added static method to get handle exceptions
 ******************************************************************************************************************************/
final public class RegistryErrorException
    extends Exception
{

  private static final long serialVersionUID = 1L;

  /******************************************************************************************************************************
   * Constructor with message to throw
   * @param reason String
   *****************************************************************************************************************************/
  public RegistryErrorException(String reason)
  {
    super(reason);
  }

  /******************************************************************************************************************************
   * Constructor with other exception to throw
   * @param ex Exception
   *****************************************************************************************************************************/
  public RegistryErrorException(Exception ex)
  {
    super(ex);
  }

  /******************************************************************************************************************************
   * Method returns a RegistryErrorException - either creating it new or if it is already a registryerrorexception it returns the
   * original one
   * @param ex Exception
   * @return RegistryErrorException
   *****************************************************************************************************************************/
  public static RegistryErrorException getException(Exception ex)
  {
    if(ex instanceof RegistryErrorException)
      return (RegistryErrorException)ex;
    else
      return new RegistryErrorException(ex);
  }
}
