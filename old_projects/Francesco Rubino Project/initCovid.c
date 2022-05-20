#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main()
{
	int nc, tam, gua;
	FILE* fd1;
	time_t t1;
	char buffer[1024];
	struct tm tm1;

	t1 = time(NULL);
	tm1 = *localtime(&t1);
	
	tm1.tm_mday -= 5;
	/*//SE SONO PASSATE LE 18 ANCHE IL REGISTER ODIERNO DOVREBBE ESSERE CHIUSO, PER CUI INIZIALIZZIAMO ANCHE QUELLO
	if (tm1.tm_hour  >= 18) tm1.tm_mday -= 4;
	else tm1.tm_mday -= 5;*/
	t1 = mktime(&tm1);

	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}

	//QUINTULTIMO REGISTRO
	memset(buffer, 0, strlen(buffer));
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon+1, tm1.tm_year+1900);
	nc = 5300;
	tam = 12000;
	gua = 2100;

	if (chdir("port5001") == -1)
	{
		mkdir("port5001", S_IRWXU);
		chdir("port5001");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	
	chdir("../..");
	if (chdir("port5002") == -1)
	{
		mkdir("port5002", S_IRWXU);
		chdir("port5002");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);

	chdir("../..");
	if (chdir("port5003") == -1)
	{
		mkdir("port5003", S_IRWXU);
		chdir("port5003");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	tm1.tm_mday++;
	t1 = mktime(&tm1);

	//QUARTULTIMO REGISTRO
	memset(buffer, 0, strlen(buffer));
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon+1, tm1.tm_year+1900);
	nc = 6200;
	tam = 22000;
	gua = 2400;

	chdir("../..");
	if (chdir("port5003") == -1)
	{
		mkdir("port5003", S_IRWXU);
		chdir("port5003");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	
	chdir("../..");
	if (chdir("port5004") == -1)
	{
		mkdir("port5004", S_IRWXU);
		chdir("port5004");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);

	chdir("../..");
	if (chdir("port5005") == -1)
	{
		mkdir("port5005", S_IRWXU);
		chdir("port5005");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	tm1.tm_mday++;
	t1 = mktime(&tm1);

	//TERZULTIMO REGISTRO
	memset(buffer, 0, strlen(buffer));
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon+1, tm1.tm_year+1900);
	nc = 5700;
	tam = 18000;
	gua = 1200;

	chdir("../..");
	if (chdir("port5002") == -1)
	{
		mkdir("port5002", S_IRWXU);
		chdir("port5002");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	
	chdir("../..");
	if (chdir("port5003") == -1)
	{
		mkdir("port5003", S_IRWXU);
		chdir("port5003");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);

	chdir("../..");
	if (chdir("port5005") == -1)
	{
		mkdir("port5005", S_IRWXU);
		chdir("port5005");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	tm1.tm_mday++;
	t1 = mktime(&tm1);

	//PENULTIMO REGISTRO
	memset(buffer, 0, strlen(buffer));
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon+1, tm1.tm_year+1900);
	nc = 7500;
	tam = 25000;
	gua = 1800;

	chdir("../..");
	if (chdir("port5001") == -1)
	{
		mkdir("port5001", S_IRWXU);
		chdir("port5001");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	
	chdir("../..");
	if (chdir("port5004") == -1)
	{
		mkdir("port5004", S_IRWXU);
		chdir("port5004");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);
	tm1.tm_mday++;
	t1 = mktime(&tm1);

	//ULTIMO REGISTRO
	memset(buffer, 0, strlen(buffer));
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon+1, tm1.tm_year+1900);
	nc = 6100;
	tam = 22000;
	gua = 3700;
	
	chdir("../..");
	if (chdir("port5003") == -1)
	{
		mkdir("port5003", S_IRWXU);
		chdir("port5003");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);

	chdir("../..");
	if (chdir("port5004") == -1)
	{
		mkdir("port5004", S_IRWXU);
		chdir("port5004");
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(buffer, "w");
	fprintf(fd1, "nuoviCasi %i tamponi %i guarigioni %i", nc, tam, gua);
	fclose(fd1);

	printf("\nRegister di prova inseriti con successo!\n\n");
	return 0;
}
