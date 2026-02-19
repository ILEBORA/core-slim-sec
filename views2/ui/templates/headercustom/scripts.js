appLayouts.addMenu('#menu');
appLayouts.addMenu('#burger');
appLayouts.addMenu('#header');
// appLayouts.addMenu('.overlay');

// Open Close Navbar Menu on Click Burger
appLayouts.addListener('click', '#burger', function () {
   var clicked = $(this).hasClass('is-active');
   const $burgerMenu = appLayouts.getMenu('burger');
   const $navbarMenu = appLayouts.getMenu('menu');

   if ($burgerMenu && $navbarMenu) {
      if(clicked){
         //remove
         $burgerMenu.removeClass('is-active');
         $navbarMenu.removeClass('is-active');
      }else{
         //add
         $burgerMenu.addClass('is-active');
         $navbarMenu.addClass('is-active');
      }
      
   }
});

// Close Navbar Menu on Click Links
appLayouts.addListener('click', '.menu-link', function () {
   appLayouts.closeMenus();
});


//cart
// Add elements to appLayouts
appLayouts.addMenu('#cart');
appLayouts.addMenu('.overlay');

// Add listener for the cart button to open cart and overlay
appLayouts.addListener('click', '#cart-btn', function () {
   appLayouts.openCartMenu();
});

appLayouts.addMethods({
   closeMenus(){
      const $cart = appLayouts.getMenu('cart');
      const $bgOverlay = appLayouts.getMenu('overlay');
      
      if ($cart && $bgOverlay) {
         $cart.removeClass('is-active');
         $bgOverlay.removeClass('is-active');
      } 
      
      const $burgerMenu = appLayouts.getMenu('burger');
      const $navbarMenu = appLayouts.getMenu('menu');
      
      if ($burgerMenu && $navbarMenu) {
         $burgerMenu.removeClass('is-active');
         $navbarMenu.removeClass('is-active');
      }
   },
   openCartMenu(){
      // alert('openCartMenu');
      const $cart       = appLayouts.getMenu('cart');
      const $bgOverlay  = appLayouts.getMenu('overlay');
      // alert('he');
      if ($cart && $bgOverlay) {
         $cart.toggleClass('is-active');
         $bgOverlay.toggleClass('is-active');
      }
   }
});

// Add listener for the overlay to close the cart and overlay
appLayouts.addListener('click', '.overlay', function () {
   appLayouts.closeMenus();
});

// Check local storage for saved mode
// if (localStorage.getItem('mode') === 'dark') {
//       $('body').addClass("dark-mode");
//       $('#mode-icon').removeClass("fa-sun").addClass("fa-moon");
// }

// appLayouts.addListener('click', '#mode-toggle', function () {
//    $('body').toggleClass("dark-mode");

//    // Change the icon
//    if ($('body').hasClass("dark-mode")) {
//       $('#mode-icon').removeClass("fa-sun").addClass("fa-moon"); // Change to moon icon
//       localStorage.setItem('mode', 'dark'); // Save mode to local storage
//    } else {
//       $('#mode-icon').removeClass("fa-moon").addClass("fa-sun"); // Change to sun icon
//       localStorage.setItem('mode', 'light'); // Save mode to local storage
//    }
// });

// // Fixed Navbar Menu on Window Resize
window.addEventListener("resize", () => {
   if (window.innerWidth >= 992) {
      appLayouts.closeMenus();
   }
});



$(document).ready(function(){
   //TODO::highlight
   $('*').each(function() {
      // Check inline styles
      const inlineStyle = $(this).attr('style');
      if (inlineStyle && inlineStyle.includes('var(')) {
          $(this).css('outline', '2px solid red'); // Highlight element with red outline
          return; // Skip further checks since it's already highlighted
      }
  });
});