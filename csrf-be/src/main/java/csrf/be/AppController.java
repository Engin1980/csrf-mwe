package csrf.be;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AppController {

  @GetMapping
  public void get(){
    // blank
  }

  @PostMapping
  public void post(){
    // blank
  }
}
