/*
 * TestNG class example
 */
package ss7fw.tests;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestNg1 {
    @Test
    public void testPrintMessage() {
        Assert.assertEquals("test", "test");
    }
    
    @Test
    public void testPrintMessage2() {
        Assert.assertEquals("test", "test");
    }
}
