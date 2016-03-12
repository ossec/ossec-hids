#include <string.h> 
const char* GeoIP_time_zone_by_country_and_region(const char * country,const char * region) {
    const char* timezone = NULL;
    if (country == NULL) {
      return NULL;
    }
    if (region == NULL) {
        region = "";
    }
    if ( strcmp (country, "AD") == 0 ) {
        return "Europe/Andorra";
    }
    if ( strcmp (country, "AE") == 0 ) {
        return "Asia/Dubai";
    }
    if ( strcmp (country, "AF") == 0 ) {
        return "Asia/Kabul";
    }
    if ( strcmp (country, "AG") == 0 ) {
        return "America/Antigua";
    }
    if ( strcmp (country, "AI") == 0 ) {
        return "America/Anguilla";
    }
    if ( strcmp (country, "AL") == 0 ) {
        return "Europe/Tirane";
    }
    if ( strcmp (country, "AM") == 0 ) {
        return "Asia/Yerevan";
    }
    if ( strcmp (country, "AN") == 0 ) {
        return "America/Curacao";
    }
    if ( strcmp (country, "AO") == 0 ) {
        return "Africa/Luanda";
    }
    if ( strcmp (country, "AQ") == 0 ) {
        return "Antarctica/South_Pole";
    }
    if ( strcmp (country, "AR") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "America/Argentina/Catamarca";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "America/Argentina/Tucuman";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "America/Argentina/Rio_Gallegos";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "America/Argentina/Cordoba";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "America/Argentina/Tucuman";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "America/Argentina/Tucuman";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "America/Argentina/Jujuy";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "America/Argentina/San_Luis";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "America/Argentina/La_Rioja";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "America/Argentina/Mendoza";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "America/Argentina/San_Luis";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "America/Argentina/Salta";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "America/Argentina/San_Juan";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "America/Argentina/San_Luis";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "America/Argentina/Rio_Gallegos";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "America/Argentina/Buenos_Aires";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "America/Argentina/Catamarca";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "America/Argentina/Ushuaia";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "America/Argentina/Tucuman";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "AS") == 0 ) {
        return "Pacific/Pago_Pago";
    }
    if ( strcmp (country, "AT") == 0 ) {
        return "Europe/Vienna";
    }
    if ( strcmp (country, "AU") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Australia/Sydney";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Australia/Sydney";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Australia/Darwin";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Australia/Brisbane";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Australia/Adelaide";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Australia/Hobart";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Australia/Melbourne";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Australia/Perth";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "AW") == 0 ) {
        return "America/Aruba";
    }
    if ( strcmp (country, "AX") == 0 ) {
        return "Europe/Mariehamn";
    }
    if ( strcmp (country, "AZ") == 0 ) {
        return "Asia/Baku";
    }
    if ( strcmp (country, "BA") == 0 ) {
        return "Europe/Sarajevo";
    }
    if ( strcmp (country, "BB") == 0 ) {
        return "America/Barbados";
    }
    if ( strcmp (country, "BD") == 0 ) {
        return "Asia/Dhaka";
    }
    if ( strcmp (country, "BE") == 0 ) {
        return "Europe/Brussels";
    }
    if ( strcmp (country, "BF") == 0 ) {
        return "Africa/Ouagadougou";
    }
    if ( strcmp (country, "BG") == 0 ) {
        return "Europe/Sofia";
    }
    if ( strcmp (country, "BH") == 0 ) {
        return "Asia/Bahrain";
    }
    if ( strcmp (country, "BI") == 0 ) {
        return "Africa/Bujumbura";
    }
    if ( strcmp (country, "BJ") == 0 ) {
        return "Africa/Porto-Novo";
    }
    if ( strcmp (country, "BL") == 0 ) {
        return "America/St_Barthelemy";
    }
    if ( strcmp (country, "BM") == 0 ) {
        return "Atlantic/Bermuda";
    }
    if ( strcmp (country, "BN") == 0 ) {
        return "Asia/Brunei";
    }
    if ( strcmp (country, "BO") == 0 ) {
        return "America/La_Paz";
    }
    if ( strcmp (country, "BQ") == 0 ) {
        return "America/Curacao";
    }
    if ( strcmp (country, "BR") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "America/Rio_Branco";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "America/Maceio";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "America/Manaus";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "America/Bahia";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "America/Fortaleza";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "America/Campo_Grande";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "America/Belem";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "America/Cuiaba";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "America/Belem";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "America/Recife";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "America/Fortaleza";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "America/Recife";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "America/Porto_Velho";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "America/Boa_Vista";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "27") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "28") == 0 ) {
            return "America/Maceio";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "America/Sao_Paulo";
        }
        else if ( strcmp (region, "30") == 0 ) {
            return "America/Recife";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "America/Araguaina";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "BS") == 0 ) {
        return "America/Nassau";
    }
    if ( strcmp (country, "BT") == 0 ) {
        return "Asia/Thimphu";
    }
    if ( strcmp (country, "BV") == 0 ) {
        return "Antarctica/Syowa";
    }
    if ( strcmp (country, "BW") == 0 ) {
        return "Africa/Gaborone";
    }
    if ( strcmp (country, "BY") == 0 ) {
        return "Europe/Minsk";
    }
    if ( strcmp (country, "BZ") == 0 ) {
        return "America/Belize";
    }
    if ( strcmp (country, "CA") == 0 ) {
        if ( strcmp (region, "AB") == 0 ) {
            return "America/Edmonton";
        }
        else if ( strcmp (region, "BC") == 0 ) {
            return "America/Vancouver";
        }
        else if ( strcmp (region, "MB") == 0 ) {
            return "America/Winnipeg";
        }
        else if ( strcmp (region, "NB") == 0 ) {
            return "America/Halifax";
        }
        else if ( strcmp (region, "NL") == 0 ) {
            return "America/St_Johns";
        }
        else if ( strcmp (region, "NS") == 0 ) {
            return "America/Halifax";
        }
        else if ( strcmp (region, "NT") == 0 ) {
            return "America/Yellowknife";
        }
        else if ( strcmp (region, "NU") == 0 ) {
            return "America/Rankin_Inlet";
        }
        else if ( strcmp (region, "ON") == 0 ) {
            return "America/Toronto";
        }
        else if ( strcmp (region, "PE") == 0 ) {
            return "America/Halifax";
        }
        else if ( strcmp (region, "QC") == 0 ) {
            return "America/Montreal";
        }
        else if ( strcmp (region, "SK") == 0 ) {
            return "America/Regina";
        }
        else if ( strcmp (region, "YT") == 0 ) {
            return "America/Whitehorse";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "CC") == 0 ) {
        return "Indian/Cocos";
    }
    if ( strcmp (country, "CD") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Africa/Kinshasa";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Africa/Kinshasa";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Africa/Kinshasa";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Africa/Kinshasa";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Africa/Kinshasa";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Africa/Lubumbashi";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "CF") == 0 ) {
        return "Africa/Bangui";
    }
    if ( strcmp (country, "CG") == 0 ) {
        return "Africa/Brazzaville";
    }
    if ( strcmp (country, "CH") == 0 ) {
        return "Europe/Zurich";
    }
    if ( strcmp (country, "CI") == 0 ) {
        return "Africa/Abidjan";
    }
    if ( strcmp (country, "CK") == 0 ) {
        return "Pacific/Rarotonga";
    }
    if ( strcmp (country, "CL") == 0 ) {
        return "America/Santiago";
    }
    if ( strcmp (country, "CM") == 0 ) {
        return "Africa/Lagos";
    }
    if ( strcmp (country, "CN") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Harbin";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Asia/Harbin";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Urumqi";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "Asia/Harbin";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Asia/Harbin";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "Asia/Harbin";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "28") == 0 ) {
            return "Asia/Shanghai";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "30") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "32") == 0 ) {
            return "Asia/Chongqing";
        }
        else if ( strcmp (region, "33") == 0 ) {
            return "Asia/Chongqing";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "CO") == 0 ) {
        return "America/Bogota";
    }
    if ( strcmp (country, "CR") == 0 ) {
        return "America/Costa_Rica";
    }
    if ( strcmp (country, "CU") == 0 ) {
        return "America/Havana";
    }
    if ( strcmp (country, "CV") == 0 ) {
        return "Atlantic/Cape_Verde";
    }
    if ( strcmp (country, "CW") == 0 ) {
        return "America/Curacao";
    }
    if ( strcmp (country, "CX") == 0 ) {
        return "Indian/Christmas";
    }
    if ( strcmp (country, "CY") == 0 ) {
        return "Asia/Nicosia";
    }
    if ( strcmp (country, "CZ") == 0 ) {
        return "Europe/Prague";
    }
    if ( strcmp (country, "DE") == 0 ) {
        return "Europe/Berlin";
    }
    if ( strcmp (country, "DJ") == 0 ) {
        return "Africa/Djibouti";
    }
    if ( strcmp (country, "DK") == 0 ) {
        return "Europe/Copenhagen";
    }
    if ( strcmp (country, "DM") == 0 ) {
        return "America/Dominica";
    }
    if ( strcmp (country, "DO") == 0 ) {
        return "America/Santo_Domingo";
    }
    if ( strcmp (country, "DZ") == 0 ) {
        return "Africa/Algiers";
    }
    if ( strcmp (country, "EC") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Pacific/Galapagos";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "America/Guayaquil";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "America/Guayaquil";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "EE") == 0 ) {
        return "Europe/Tallinn";
    }
    if ( strcmp (country, "EG") == 0 ) {
        return "Africa/Cairo";
    }
    if ( strcmp (country, "EH") == 0 ) {
        return "Africa/El_Aaiun";
    }
    if ( strcmp (country, "ER") == 0 ) {
        return "Africa/Asmara";
    }
    if ( strcmp (country, "ES") == 0 ) {
        if ( strcmp (region, "07") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "27") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "32") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "34") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "39") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "51") == 0 ) {
            return "Africa/Ceuta";
        }
        else if ( strcmp (region, "52") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "53") == 0 ) {
            return "Atlantic/Canary";
        }
        else if ( strcmp (region, "54") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "55") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "56") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "57") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "58") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "59") == 0 ) {
            return "Europe/Madrid";
        }
        else if ( strcmp (region, "60") == 0 ) {
            return "Europe/Madrid";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "ET") == 0 ) {
        return "Africa/Addis_Ababa";
    }
    if ( strcmp (country, "FI") == 0 ) {
        return "Europe/Helsinki";
    }
    if ( strcmp (country, "FJ") == 0 ) {
        return "Pacific/Fiji";
    }
    if ( strcmp (country, "FK") == 0 ) {
        return "Atlantic/Stanley";
    }
    if ( strcmp (country, "FM") == 0 ) {
        return "Pacific/Pohnpei";
    }
    if ( strcmp (country, "FO") == 0 ) {
        return "Atlantic/Faroe";
    }
    if ( strcmp (country, "FR") == 0 ) {
        return "Europe/Paris";
    }
    if ( strcmp (country, "FX") == 0 ) {
        return "Europe/Paris";
    }
    if ( strcmp (country, "GA") == 0 ) {
        return "Africa/Libreville";
    }
    if ( strcmp (country, "GB") == 0 ) {
        return "Europe/London";
    }
    if ( strcmp (country, "GD") == 0 ) {
        return "America/Grenada";
    }
    if ( strcmp (country, "GE") == 0 ) {
        return "Asia/Tbilisi";
    }
    if ( strcmp (country, "GF") == 0 ) {
        return "America/Cayenne";
    }
    if ( strcmp (country, "GG") == 0 ) {
        return "Europe/Guernsey";
    }
    if ( strcmp (country, "GH") == 0 ) {
        return "Africa/Accra";
    }
    if ( strcmp (country, "GI") == 0 ) {
        return "Europe/Gibraltar";
    }
    if ( strcmp (country, "GL") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "America/Thule";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "America/Godthab";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "America/Godthab";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "GM") == 0 ) {
        return "Africa/Banjul";
    }
    if ( strcmp (country, "GN") == 0 ) {
        return "Africa/Conakry";
    }
    if ( strcmp (country, "GP") == 0 ) {
        return "America/Guadeloupe";
    }
    if ( strcmp (country, "GQ") == 0 ) {
        return "Africa/Malabo";
    }
    if ( strcmp (country, "GR") == 0 ) {
        return "Europe/Athens";
    }
    if ( strcmp (country, "GS") == 0 ) {
        return "Atlantic/South_Georgia";
    }
    if ( strcmp (country, "GT") == 0 ) {
        return "America/Guatemala";
    }
    if ( strcmp (country, "GU") == 0 ) {
        return "Pacific/Guam";
    }
    if ( strcmp (country, "GW") == 0 ) {
        return "Africa/Bissau";
    }
    if ( strcmp (country, "GY") == 0 ) {
        return "America/Guyana";
    }
    if ( strcmp (country, "HK") == 0 ) {
        return "Asia/Hong_Kong";
    }
    if ( strcmp (country, "HN") == 0 ) {
        return "America/Tegucigalpa";
    }
    if ( strcmp (country, "HR") == 0 ) {
        return "Europe/Zagreb";
    }
    if ( strcmp (country, "HT") == 0 ) {
        return "America/Port-au-Prince";
    }
    if ( strcmp (country, "HU") == 0 ) {
        return "Europe/Budapest";
    }
    if ( strcmp (country, "ID") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Asia/Jayapura";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "28") == 0 ) {
            return "Asia/Jayapura";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "30") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "32") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "33") == 0 ) {
            return "Asia/Jakarta";
        }
        else if ( strcmp (region, "34") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "35") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "36") == 0 ) {
            return "Asia/Jayapura";
        }
        else if ( strcmp (region, "37") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "38") == 0 ) {
            return "Asia/Makassar";
        }
        else if ( strcmp (region, "39") == 0 ) {
            return "Asia/Jayapura";
        }
        else if ( strcmp (region, "40") == 0 ) {
            return "Asia/Pontianak";
        }
        else if ( strcmp (region, "41") == 0 ) {
            return "Asia/Makassar";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "IE") == 0 ) {
        return "Europe/Dublin";
    }
    if ( strcmp (country, "IL") == 0 ) {
        return "Asia/Jerusalem";
    }
    if ( strcmp (country, "IM") == 0 ) {
        return "Europe/Isle_of_Man";
    }
    if ( strcmp (country, "IN") == 0 ) {
        return "Asia/Kolkata";
    }
    if ( strcmp (country, "IO") == 0 ) {
        return "Indian/Chagos";
    }
    if ( strcmp (country, "IQ") == 0 ) {
        return "Asia/Baghdad";
    }
    if ( strcmp (country, "IR") == 0 ) {
        return "Asia/Tehran";
    }
    if ( strcmp (country, "IS") == 0 ) {
        return "Atlantic/Reykjavik";
    }
    if ( strcmp (country, "IT") == 0 ) {
        return "Europe/Rome";
    }
    if ( strcmp (country, "JE") == 0 ) {
        return "Europe/Jersey";
    }
    if ( strcmp (country, "JM") == 0 ) {
        return "America/Jamaica";
    }
    if ( strcmp (country, "JO") == 0 ) {
        return "Asia/Amman";
    }
    if ( strcmp (country, "JP") == 0 ) {
        return "Asia/Tokyo";
    }
    if ( strcmp (country, "KE") == 0 ) {
        return "Africa/Nairobi";
    }
    if ( strcmp (country, "KG") == 0 ) {
        return "Asia/Bishkek";
    }
    if ( strcmp (country, "KH") == 0 ) {
        return "Asia/Phnom_Penh";
    }
    if ( strcmp (country, "KI") == 0 ) {
        return "Pacific/Tarawa";
    }
    if ( strcmp (country, "KM") == 0 ) {
        return "Indian/Comoro";
    }
    if ( strcmp (country, "KN") == 0 ) {
        return "America/St_Kitts";
    }
    if ( strcmp (country, "KP") == 0 ) {
        return "Asia/Pyongyang";
    }
    if ( strcmp (country, "KR") == 0 ) {
        return "Asia/Seoul";
    }
    if ( strcmp (country, "KW") == 0 ) {
        return "Asia/Kuwait";
    }
    if ( strcmp (country, "KY") == 0 ) {
        return "America/Cayman";
    }
    if ( strcmp (country, "KZ") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Asia/Almaty";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Almaty";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Asia/Aqtobe";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Asia/Aqtau";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Asia/Oral";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Asia/Aqtau";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Almaty";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Aqtobe";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Qyzylorda";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Asia/Almaty";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Asia/Aqtobe";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Asia/Almaty";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "LA") == 0 ) {
        return "Asia/Vientiane";
    }
    if ( strcmp (country, "LB") == 0 ) {
        return "Asia/Beirut";
    }
    if ( strcmp (country, "LC") == 0 ) {
        return "America/St_Lucia";
    }
    if ( strcmp (country, "LI") == 0 ) {
        return "Europe/Vaduz";
    }
    if ( strcmp (country, "LK") == 0 ) {
        return "Asia/Colombo";
    }
    if ( strcmp (country, "LR") == 0 ) {
        return "Africa/Monrovia";
    }
    if ( strcmp (country, "LS") == 0 ) {
        return "Africa/Maseru";
    }
    if ( strcmp (country, "LT") == 0 ) {
        return "Europe/Vilnius";
    }
    if ( strcmp (country, "LU") == 0 ) {
        return "Europe/Luxembourg";
    }
    if ( strcmp (country, "LV") == 0 ) {
        return "Europe/Riga";
    }
    if ( strcmp (country, "LY") == 0 ) {
        return "Africa/Tripoli";
    }
    if ( strcmp (country, "MA") == 0 ) {
        return "Africa/Casablanca";
    }
    if ( strcmp (country, "MC") == 0 ) {
        return "Europe/Monaco";
    }
    if ( strcmp (country, "MD") == 0 ) {
        return "Europe/Chisinau";
    }
    if ( strcmp (country, "ME") == 0 ) {
        return "Europe/Podgorica";
    }
    if ( strcmp (country, "MF") == 0 ) {
        return "America/Marigot";
    }
    if ( strcmp (country, "MG") == 0 ) {
        return "Indian/Antananarivo";
    }
    if ( strcmp (country, "MH") == 0 ) {
        return "Pacific/Kwajalein";
    }
    if ( strcmp (country, "MK") == 0 ) {
        return "Europe/Skopje";
    }
    if ( strcmp (country, "ML") == 0 ) {
        return "Africa/Bamako";
    }
    if ( strcmp (country, "MM") == 0 ) {
        return "Asia/Rangoon";
    }
    if ( strcmp (country, "MN") == 0 ) {
        if ( strcmp (region, "06") == 0 ) {
            return "Asia/Choibalsan";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Ulaanbaatar";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Asia/Choibalsan";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "Asia/Hovd";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Asia/Ulaanbaatar";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Asia/Ulaanbaatar";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "Asia/Ulaanbaatar";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "MO") == 0 ) {
        return "Asia/Macau";
    }
    if ( strcmp (country, "MP") == 0 ) {
        return "Pacific/Saipan";
    }
    if ( strcmp (country, "MQ") == 0 ) {
        return "America/Martinique";
    }
    if ( strcmp (country, "MR") == 0 ) {
        return "Africa/Nouakchott";
    }
    if ( strcmp (country, "MS") == 0 ) {
        return "America/Montserrat";
    }
    if ( strcmp (country, "MT") == 0 ) {
        return "Europe/Malta";
    }
    if ( strcmp (country, "MU") == 0 ) {
        return "Indian/Mauritius";
    }
    if ( strcmp (country, "MV") == 0 ) {
        return "Indian/Maldives";
    }
    if ( strcmp (country, "MW") == 0 ) {
        return "Africa/Blantyre";
    }
    if ( strcmp (country, "MX") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "America/Tijuana";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "America/Hermosillo";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "America/Merida";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "America/Chihuahua";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "America/Monterrey";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "America/Mazatlan";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "America/Mazatlan";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "America/Chihuahua";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "America/Mazatlan";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "America/Monterrey";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "America/Cancun";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "America/Mazatlan";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "America/Hermosillo";
        }
        else if ( strcmp (region, "27") == 0 ) {
            return "America/Merida";
        }
        else if ( strcmp (region, "28") == 0 ) {
            return "America/Monterrey";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "30") == 0 ) {
            return "America/Mexico_City";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "America/Merida";
        }
        else if ( strcmp (region, "32") == 0 ) {
            return "America/Monterrey";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "MY") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Kuching";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Kuala_Lumpur";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Asia/Kuching";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Asia/Kuching";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "MZ") == 0 ) {
        return "Africa/Maputo";
    }
    if ( strcmp (country, "NA") == 0 ) {
        return "Africa/Windhoek";
    }
    if ( strcmp (country, "NC") == 0 ) {
        return "Pacific/Noumea";
    }
    if ( strcmp (country, "NE") == 0 ) {
        return "Africa/Niamey";
    }
    if ( strcmp (country, "NF") == 0 ) {
        return "Pacific/Norfolk";
    }
    if ( strcmp (country, "NG") == 0 ) {
        return "Africa/Lagos";
    }
    if ( strcmp (country, "NI") == 0 ) {
        return "America/Managua";
    }
    if ( strcmp (country, "NL") == 0 ) {
        return "Europe/Amsterdam";
    }
    if ( strcmp (country, "NO") == 0 ) {
        return "Europe/Oslo";
    }
    if ( strcmp (country, "NP") == 0 ) {
        return "Asia/Kathmandu";
    }
    if ( strcmp (country, "NR") == 0 ) {
        return "Pacific/Nauru";
    }
    if ( strcmp (country, "NU") == 0 ) {
        return "Pacific/Niue";
    }
    if ( strcmp (country, "NZ") == 0 ) {
        if ( strcmp (region, "85") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "E7") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "E8") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "E9") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F1") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F2") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F3") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F4") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F5") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F6") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F7") == 0 ) {
            return "Pacific/Chatham";
        }
        else if ( strcmp (region, "F8") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "F9") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "G1") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "G2") == 0 ) {
            return "Pacific/Auckland";
        }
        else if ( strcmp (region, "G3") == 0 ) {
            return "Pacific/Auckland";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "OM") == 0 ) {
        return "Asia/Muscat";
    }
    if ( strcmp (country, "PA") == 0 ) {
        return "America/Panama";
    }
    if ( strcmp (country, "PE") == 0 ) {
        return "America/Lima";
    }
    if ( strcmp (country, "PF") == 0 ) {
        return "Pacific/Marquesas";
    }
    if ( strcmp (country, "PG") == 0 ) {
        return "Pacific/Port_Moresby";
    }
    if ( strcmp (country, "PH") == 0 ) {
        return "Asia/Manila";
    }
    if ( strcmp (country, "PK") == 0 ) {
        return "Asia/Karachi";
    }
    if ( strcmp (country, "PL") == 0 ) {
        return "Europe/Warsaw";
    }
    if ( strcmp (country, "PM") == 0 ) {
        return "America/Miquelon";
    }
    if ( strcmp (country, "PN") == 0 ) {
        return "Pacific/Pitcairn";
    }
    if ( strcmp (country, "PR") == 0 ) {
        return "America/Puerto_Rico";
    }
    if ( strcmp (country, "PS") == 0 ) {
        return "Asia/Gaza";
    }
    if ( strcmp (country, "PT") == 0 ) {
        if ( strcmp (region, "02") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Atlantic/Madeira";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "Europe/Lisbon";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "Atlantic/Azores";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "PW") == 0 ) {
        return "Pacific/Palau";
    }
    if ( strcmp (country, "PY") == 0 ) {
        return "America/Asuncion";
    }
    if ( strcmp (country, "QA") == 0 ) {
        return "Asia/Qatar";
    }
    if ( strcmp (country, "RE") == 0 ) {
        return "Indian/Reunion";
    }
    if ( strcmp (country, "RO") == 0 ) {
        return "Europe/Bucharest";
    }
    if ( strcmp (country, "RS") == 0 ) {
        return "Europe/Belgrade";
    }
    if ( strcmp (country, "RU") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Novokuznetsk";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Asia/Novosibirsk";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Vladivostok";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Asia/Anadyr";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "Asia/Krasnoyarsk";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "Europe/Kaliningrad";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "Asia/Kamchatka";
        }
        else if ( strcmp (region, "27") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "28") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "29") == 0 ) {
            return "Asia/Novokuznetsk";
        }
        else if ( strcmp (region, "30") == 0 ) {
            return "Asia/Vladivostok";
        }
        else if ( strcmp (region, "31") == 0 ) {
            return "Asia/Krasnoyarsk";
        }
        else if ( strcmp (region, "32") == 0 ) {
            return "Asia/Omsk";
        }
        else if ( strcmp (region, "33") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "34") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "35") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "36") == 0 ) {
            return "Asia/Anadyr";
        }
        else if ( strcmp (region, "37") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "38") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "39") == 0 ) {
            return "Asia/Krasnoyarsk";
        }
        else if ( strcmp (region, "40") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "41") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "42") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "43") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "44") == 0 ) {
            return "Asia/Magadan";
        }
        else if ( strcmp (region, "45") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "46") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "47") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "48") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "49") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "50") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "51") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "52") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "53") == 0 ) {
            return "Asia/Novosibirsk";
        }
        else if ( strcmp (region, "54") == 0 ) {
            return "Asia/Omsk";
        }
        else if ( strcmp (region, "55") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "56") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "57") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "58") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "59") == 0 ) {
            return "Asia/Vladivostok";
        }
        else if ( strcmp (region, "60") == 0 ) {
            return "Europe/Kaliningrad";
        }
        else if ( strcmp (region, "61") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "62") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "63") == 0 ) {
            return "Asia/Yakutsk";
        }
        else if ( strcmp (region, "64") == 0 ) {
            return "Asia/Sakhalin";
        }
        else if ( strcmp (region, "65") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "66") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "67") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "68") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "69") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "70") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "71") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "72") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "73") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "74") == 0 ) {
            return "Asia/Krasnoyarsk";
        }
        else if ( strcmp (region, "75") == 0 ) {
            return "Asia/Novosibirsk";
        }
        else if ( strcmp (region, "76") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "77") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "78") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "79") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "80") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "81") == 0 ) {
            return "Europe/Samara";
        }
        else if ( strcmp (region, "82") == 0 ) {
            return "Asia/Irkutsk";
        }
        else if ( strcmp (region, "83") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "84") == 0 ) {
            return "Europe/Volgograd";
        }
        else if ( strcmp (region, "85") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "86") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "87") == 0 ) {
            return "Asia/Novosibirsk";
        }
        else if ( strcmp (region, "88") == 0 ) {
            return "Europe/Moscow";
        }
        else if ( strcmp (region, "89") == 0 ) {
            return "Asia/Vladivostok";
        }
        else if ( strcmp (region, "90") == 0 ) {
            return "Asia/Yekaterinburg";
        }
        else if ( strcmp (region, "91") == 0 ) {
            return "Asia/Krasnoyarsk";
        }
        else if ( strcmp (region, "92") == 0 ) {
            return "Asia/Anadyr";
        }
        else if ( strcmp (region, "93") == 0 ) {
            return "Asia/Irkutsk";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "RW") == 0 ) {
        return "Africa/Kigali";
    }
    if ( strcmp (country, "SA") == 0 ) {
        return "Asia/Riyadh";
    }
    if ( strcmp (country, "SB") == 0 ) {
        return "Pacific/Guadalcanal";
    }
    if ( strcmp (country, "SC") == 0 ) {
        return "Indian/Mahe";
    }
    if ( strcmp (country, "SD") == 0 ) {
        return "Africa/Khartoum";
    }
    if ( strcmp (country, "SE") == 0 ) {
        return "Europe/Stockholm";
    }
    if ( strcmp (country, "SG") == 0 ) {
        return "Asia/Singapore";
    }
    if ( strcmp (country, "SH") == 0 ) {
        return "Atlantic/St_Helena";
    }
    if ( strcmp (country, "SI") == 0 ) {
        return "Europe/Ljubljana";
    }
    if ( strcmp (country, "SJ") == 0 ) {
        return "Arctic/Longyearbyen";
    }
    if ( strcmp (country, "SK") == 0 ) {
        return "Europe/Bratislava";
    }
    if ( strcmp (country, "SL") == 0 ) {
        return "Africa/Freetown";
    }
    if ( strcmp (country, "SM") == 0 ) {
        return "Europe/San_Marino";
    }
    if ( strcmp (country, "SN") == 0 ) {
        return "Africa/Dakar";
    }
    if ( strcmp (country, "SO") == 0 ) {
        return "Africa/Mogadishu";
    }
    if ( strcmp (country, "SR") == 0 ) {
        return "America/Paramaribo";
    }
    if ( strcmp (country, "SS") == 0 ) {
        return "Africa/Juba";
    }
    if ( strcmp (country, "ST") == 0 ) {
        return "Africa/Sao_Tome";
    }
    if ( strcmp (country, "SV") == 0 ) {
        return "America/El_Salvador";
    }
    if ( strcmp (country, "SX") == 0 ) {
        return "America/Curacao";
    }
    if ( strcmp (country, "SY") == 0 ) {
        return "Asia/Damascus";
    }
    if ( strcmp (country, "SZ") == 0 ) {
        return "Africa/Mbabane";
    }
    if ( strcmp (country, "TC") == 0 ) {
        return "America/Grand_Turk";
    }
    if ( strcmp (country, "TD") == 0 ) {
        return "Africa/Ndjamena";
    }
    if ( strcmp (country, "TF") == 0 ) {
        return "Indian/Kerguelen";
    }
    if ( strcmp (country, "TG") == 0 ) {
        return "Africa/Lome";
    }
    if ( strcmp (country, "TH") == 0 ) {
        return "Asia/Bangkok";
    }
    if ( strcmp (country, "TJ") == 0 ) {
        return "Asia/Dushanbe";
    }
    if ( strcmp (country, "TK") == 0 ) {
        return "Pacific/Fakaofo";
    }
    if ( strcmp (country, "TL") == 0 ) {
        return "Asia/Dili";
    }
    if ( strcmp (country, "TM") == 0 ) {
        return "Asia/Ashgabat";
    }
    if ( strcmp (country, "TN") == 0 ) {
        return "Africa/Tunis";
    }
    if ( strcmp (country, "TO") == 0 ) {
        return "Pacific/Tongatapu";
    }
    if ( strcmp (country, "TR") == 0 ) {
        return "Asia/Istanbul";
    }
    if ( strcmp (country, "TT") == 0 ) {
        return "America/Port_of_Spain";
    }
    if ( strcmp (country, "TV") == 0 ) {
        return "Pacific/Funafuti";
    }
    if ( strcmp (country, "TW") == 0 ) {
        return "Asia/Taipei";
    }
    if ( strcmp (country, "TZ") == 0 ) {
        return "Africa/Dar_es_Salaam";
    }
    if ( strcmp (country, "UA") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "04") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Europe/Simferopol";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "11") == 0 ) {
            return "Europe/Simferopol";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "15") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "16") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "17") == 0 ) {
            return "Europe/Simferopol";
        }
        else if ( strcmp (region, "18") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "19") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "20") == 0 ) {
            return "Europe/Simferopol";
        }
        else if ( strcmp (region, "21") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "22") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "23") == 0 ) {
            return "Europe/Kiev";
        }
        else if ( strcmp (region, "24") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "25") == 0 ) {
            return "Europe/Uzhgorod";
        }
        else if ( strcmp (region, "26") == 0 ) {
            return "Europe/Zaporozhye";
        }
        else if ( strcmp (region, "27") == 0 ) {
            return "Europe/Kiev";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "UG") == 0 ) {
        return "Africa/Kampala";
    }
    if ( strcmp (country, "UM") == 0 ) {
        return "Pacific/Wake";
    }
    if ( strcmp (country, "US") == 0 ) {
        if ( strcmp (region, "AK") == 0 ) {
            return "America/Anchorage";
        }
        else if ( strcmp (region, "AL") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "AR") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "AZ") == 0 ) {
            return "America/Phoenix";
        }
        else if ( strcmp (region, "CA") == 0 ) {
            return "America/Los_Angeles";
        }
        else if ( strcmp (region, "CO") == 0 ) {
            return "America/Denver";
        }
        else if ( strcmp (region, "CT") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "DC") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "DE") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "FL") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "GA") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "HI") == 0 ) {
            return "Pacific/Honolulu";
        }
        else if ( strcmp (region, "IA") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "ID") == 0 ) {
            return "America/Denver";
        }
        else if ( strcmp (region, "IL") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "IN") == 0 ) {
            return "America/Indiana/Indianapolis";
        }
        else if ( strcmp (region, "KS") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "KY") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "LA") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "MA") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "MD") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "ME") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "MI") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "MN") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "MO") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "MS") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "MT") == 0 ) {
            return "America/Denver";
        }
        else if ( strcmp (region, "NC") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "ND") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "NE") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "NH") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "NJ") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "NM") == 0 ) {
            return "America/Denver";
        }
        else if ( strcmp (region, "NV") == 0 ) {
            return "America/Los_Angeles";
        }
        else if ( strcmp (region, "NY") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "OH") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "OK") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "OR") == 0 ) {
            return "America/Los_Angeles";
        }
        else if ( strcmp (region, "PA") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "RI") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "SC") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "SD") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "TN") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "TX") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "UT") == 0 ) {
            return "America/Denver";
        }
        else if ( strcmp (region, "VA") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "VT") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "WA") == 0 ) {
            return "America/Los_Angeles";
        }
        else if ( strcmp (region, "WI") == 0 ) {
            return "America/Chicago";
        }
        else if ( strcmp (region, "WV") == 0 ) {
            return "America/New_York";
        }
        else if ( strcmp (region, "WY") == 0 ) {
            return "America/Denver";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "UY") == 0 ) {
        return "America/Montevideo";
    }
    if ( strcmp (country, "UZ") == 0 ) {
        if ( strcmp (region, "01") == 0 ) {
            return "Asia/Tashkent";
        }
        else if ( strcmp (region, "02") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "03") == 0 ) {
            return "Asia/Tashkent";
        }
        else if ( strcmp (region, "05") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "06") == 0 ) {
            return "Asia/Tashkent";
        }
        else if ( strcmp (region, "07") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "08") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "09") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "10") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "12") == 0 ) {
            return "Asia/Samarkand";
        }
        else if ( strcmp (region, "13") == 0 ) {
            return "Asia/Tashkent";
        }
        else if ( strcmp (region, "14") == 0 ) {
            return "Asia/Tashkent";
        }
        else {
             return NULL;
        }
    }
    if ( strcmp (country, "VA") == 0 ) {
        return "Europe/Vatican";
    }
    if ( strcmp (country, "VC") == 0 ) {
        return "America/St_Vincent";
    }
    if ( strcmp (country, "VE") == 0 ) {
        return "America/Caracas";
    }
    if ( strcmp (country, "VG") == 0 ) {
        return "America/Tortola";
    }
    if ( strcmp (country, "VI") == 0 ) {
        return "America/St_Thomas";
    }
    if ( strcmp (country, "VN") == 0 ) {
        return "Asia/Phnom_Penh";
    }
    if ( strcmp (country, "VU") == 0 ) {
        return "Pacific/Efate";
    }
    if ( strcmp (country, "WF") == 0 ) {
        return "Pacific/Wallis";
    }
    if ( strcmp (country, "WS") == 0 ) {
        return "Pacific/Pago_Pago";
    }
    if ( strcmp (country, "YE") == 0 ) {
        return "Asia/Aden";
    }
    if ( strcmp (country, "YT") == 0 ) {
        return "Indian/Mayotte";
    }
    if ( strcmp (country, "YU") == 0 ) {
        return "Europe/Belgrade";
    }
    if ( strcmp (country, "ZA") == 0 ) {
        return "Africa/Johannesburg";
    }
    if ( strcmp (country, "ZM") == 0 ) {
        return "Africa/Lusaka";
    }
    if ( strcmp (country, "ZW") == 0 ) {
        return "Africa/Harare";
    }
    return timezone;
}
