package at.jta;

import java.io.IOException;

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
 * @author <a href="mailto:joerg_t_p@gmx.at">Taschek Joerg</a>
 * @version 1.0
 ******************************************************************************************************************************/
final public class RegistryErrorException
    extends IOException
{

  /******************************************************************************************************************************
   * Constructor with message to throw
   * @param reason String
   *****************************************************************************************************************************/
  public RegistryErrorException(String reason)
  {
    super(reason);
  }
}
