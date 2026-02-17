<!--Count item widget -->
@if( $statusmode != "" ) 
@set($statustitle="<h2 class='mode_text' >Item flagged: $statusmode</h2>")
@set($itemtitle="Item not visible without permissions.")
@else
@set($statustitle="")
@set($itemtitle="")
@endif


<div class="col-xl-12 col-md-12 col-12 widget_section @($statusmode) dwidget@($id)" data-typ="@($class)" pointer fnl="@($link)" title="@($itemtitle)">
    <span class="widget_tools">@($tools) </span>
    
    <div class="wrapper count-title d-flex w-full">
        
        <div class="name">
        @($statustitle)
        <strong class="wtitle text-uppercase" style="display:none">@($title)</strong>
        <span>@($desc)</span>
        <div  class="count-number @($lvui)" lvui="@($lvui)" data-id="LiveAcc" pointer >
            @($count)
        </div>
    </div>
    </div>

    <div class="section-content">
        @($content)
    </div>

</div>