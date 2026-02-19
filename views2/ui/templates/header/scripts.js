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
   const $burgerMenu = appLayouts.getMenu('burger');
   const $navbarMenu = appLayouts.getMenu('menu');
   
   if ($burgerMenu && $navbarMenu) {
      $burgerMenu.removeClass('is-active');
      $navbarMenu.removeClass('is-active');
   }
});


//cart
// Add elements to appLayouts
appLayouts.addMenu('#cart');
appLayouts.addMenu('.overlay');

appLayouts.addMethod({
   openCartMenu(){
      alert('openCartMenu');
      const $cart       = appLayouts.getMenu('cart');
      const $bgOverlay  = appLayouts.getMenu('overlay');
      // alert('he');
      if ($cart && $bgOverlay) {
         $cart.toggleClass('is-active');
         $bgOverlay.toggleClass('is-active');
      }
   }
});

// Add listener for the cart button to open cart and overlay
appLayouts.addListener('click', '#cart-btn', function () {
   appLayouts.openCartMenu();
   // const $cart       = appLayouts.getMenu('cart');
   // const $bgOverlay  = appLayouts.getMenu('overlay');
   // // alert('he');
   // if ($cart && $bgOverlay) {
   //    $cart.toggleClass('is-active');
   //    $bgOverlay.toggleClass('is-active');
   // }
});

// Add listener for the overlay to close the cart and overlay
appLayouts.addListener('click', '.overlay', function () {
   const $cart = appLayouts.getMenu('cart');
   const $bgOverlay = appLayouts.getMenu('overlay');
   
   if ($cart && $bgOverlay) {
      $cart.removeClass('is-active');
      $bgOverlay.removeClass('is-active');
   }
});


//darkMode
appLayouts.addListener('click', '#switch', function () {

   document.documentElement.classList.toggle("dark-mode");
   document.body.classList.toggle("dark-mode");
});


// // Fixed Navbar Menu on Window Resize
$(window).on('resize', function() {
   if ($(window).width() >= 992) {
      const $navbarMenu = appLayouts.getMenu('menu');
      const $bgOverlay = appLayouts.getMenu('overlay');

      if (typeof $navbarMenu !== 'undefined') {
         if ($navbarMenu.hasClass('is-active')) {
            $navbarMenu.removeClass('is-active');
            $bgOverlay.removeClass('is-active');
         }
      }
   }
});



$(document).ready(function(){
   
});